using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using I2PCore.Crypto;
using I2PCore.Crypto.MLKEM;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer.Log;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.NTCP2;

/// <summary>
///     NTCP2 Session State
///     Tracks the handshake and data phase state
/// </summary>
public enum NTCP2SessionState
{
    Initial,
    SessionRequestSent,
    SessionRequestReceived,
    SessionCreatedSent,
    SessionCreatedReceived,
    SessionConfirmedSent,
    SessionConfirmedReceived,
    Established,
    Terminated
}

/// <summary>
///     Represents an NTCP2 session
///     Implements Noise XK handshake pattern over TCP and ITransport interface
/// </summary>
public class NTCP2Session : ITransport
{
    private readonly NTCP2Host Host;

    private readonly PeriodicAction KeepAlive = new(TickSpan.Minutes(2));

    // Receive buffer for assembling frames
    private readonly byte[] ReceiveBuffer = new byte[131072]; // 128KB to handle max frames (64KB payload + 2B len)

    // Cached deobfuscated frame length - prevents SipHash counter desync
    // when we don't have enough data for a full frame
    private ushort? _pendingFrameLength;

    // AES state (last 16 bytes of obfuscated X) for Message 2 continuation
    private byte[] AESStateAfterMsg1;
    private ushort CachedM3P2Len;

    // Saved RouterInfo for SessionConfirmed consistency
    private byte[] CachedMyRouterInfoBytes;
    private bool ClockSkewDetected;
    private bool DateTimeBlockSent;

    private bool HandshakeDecrypted;
    private byte[] HandshakeDecryptedOptions;
    private int HandshakePaddingLen;

    // ML-KEM post-quantum hybrid state
    private long LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private byte[] LocalKemPublicKey;
    private byte[] LocalKemSecretKey;
    private long NextRouterInfoResendTime;

    // Noise protocol state
    private NoiseXK NoiseState;
    private int PQVersion; // 3=MLKEM512, 4=MLKEM768, 5=MLKEM1024

    // Saved Noise state before Split() clears the chaining key.
    // Needed for SipHash key derivation which uses the original CK.
    private byte[] PreSplitChainingKey;
    private byte[] PreSplitHash;
    private int ReceiveBufferPos;
    private NTCP2SipHash ReceiveSipHash;
    private byte[] RemoteKemPublicKey;
    private ushort RemoteM3P2Len;
    private byte RemoteNetworkId;
    private byte RemoteVersion;

    // SipHash keys for frame length obfuscation
    private NTCP2SipHash SendSipHash;

    // Selected address for outbound connection
    private I2PRouterAddress SelectedAddress;

    // Constructor for outgoing connections
    public NTCP2Session(NTCP2Host host, I2PRouterInfo remoteRouter, bool isOutgoing)
    {
        Host = host;
        RemoteRouterInfo = remoteRouter;
        IsOutgoing = isOutgoing;
        State = NTCP2SessionState.Initial;
        DebugId = $"NTCP2-{(isOutgoing ? "Out" : "In")}-{BufUtils.RandomUint():X8}";

        TransportConnectionLogger.Inst.Log(
            $"Created outbound NTCP2 session to {RemoteRouterInfo?.Identity?.IdentHash?.Id32Short}",
            RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
    }

    // Constructor for incoming connections
    public NTCP2Session(NTCP2Host host, TcpClient client)
    {
        Host = host;
        TcpClient = client;
        IsOutgoing = false;
        State = NTCP2SessionState.Initial;
        DebugId = $"NTCP2-In-{BufUtils.RandomUint():X8}";

        TransportConnectionLogger.Inst.Log("Accepted inbound NTCP2 connection", null, "NTCP2", "Inbound");
    }

    public TcpClient TcpClient { get; private set; }
    public int BytesInBuffer => ReceiveBufferPos;
    public NTCP2SessionState State { get; private set; }

    public I2PRouterInfo RemoteRouterInfo { get; private set; }

    // ITransport events
    public event Action<ITransport, Exception> ConnectionException;
    public event Action<ITransport> ConnectionShutDown;
    public event Action<ITransport, I2PIdentHash> ConnectionEstablished;
    public event Action<ITransport, Ii2NpHeader> DataBlockReceived;
    public bool IsTerminated { get; private set; }
    public bool IsOutgoing { get; }

    // ITransport properties
    public IPAddress RemoteAddress => (TcpClient?.Client?.RemoteEndPoint as IPEndPoint)?.Address;
    public I2PKeysAndCert RemoteRouterIdentity => RemoteRouterInfo?.Identity;
    public long BytesSent { get; private set; }
    public long BytesReceived { get; private set; }
    public string DebugId { get; }
    public string Protocol => "NTCP2";
    public bool IsPQ { get; private set; }

    public void Connect()
    {
        if (!IsOutgoing)
            throw new InvalidOperationException("Cannot call Connect on incoming session");

        if (State != NTCP2SessionState.Initial)
            throw new InvalidOperationException($"Cannot connect from state {State}");

        // Perform connection in background to avoid blocking the caller (e.g. NetDb thread)
        Task.Run(() =>
        {
            try
            {
                // Extract endpoint from RouterInfo and store selected address
                SelectedAddress = ExtractSelectedAddress();
                var endpoint = GetEndpointFromAddress(SelectedAddress);

                // Create TCP connection (optionally through SOCKS5 proxy)
                TcpClient = new TcpClient();

                if (Socks5Client.UsingProxy)
                {
                    Socks5Client.ConnectThroughProxy(TcpClient, endpoint);
                    Logging.LogDebug($"{DebugId}: TCP connected to {endpoint} via SOCKS5 proxy");
                    TransportConnectionLogger.Inst.Log($"TCP connected to {endpoint} via SOCKS5 proxy",
                        RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
                }
                else
                {
                    // Use a reasonable timeout for TCP connection (e.g. 10s)
                    var connectTask = TcpClient.ConnectAsync(endpoint.Address, endpoint.Port);
                    if (!connectTask.Wait(10000))
                        throw new TimeoutException($"TCP connection to {endpoint} timed out after 10s");
                    Logging.LogDebug($"{DebugId}: TCP connected to {endpoint}");
                    TransportConnectionLogger.Inst.Log($"TCP connected to {endpoint}",
                        RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
                }

                // Initialize Noise protocol as Alice (initiator)
                InitializeNoiseAsAlice();

                // Send SessionRequest
                SendSessionRequest();

                State = NTCP2SessionState.SessionRequestSent;

                // Start receiving responses
                StartReceiveLoop();
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: Connect failed: {ex.Message}");
                TransportConnectionLogger.Inst.Log($"Connect failed: {ex.Message}",
                    RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "NTCP2", "Outbound");
                ConnectionException?.Invoke(this, ex);
                Terminate($"Connect failed (State: {State}): {ex.Message}");
            }
        });
    }

    public void Send(I2NpMessage msg)
    {
        if (State != NTCP2SessionState.Established)
        {
            Logging.LogWarning($"{DebugId}: Cannot send, session not established");
            return;
        }

        try
        {
            // Build data frame with I2NP message
            var encrypted = BuildDataFrame(msg);

            Logging.LogDebug($"{DebugId}: Sending data frame ({encrypted.Length} bytes) with {msg.MessageType}");

            // Send via TCP
            var stream = TcpClient.GetStream();
            stream.Write(encrypted, 0, encrypted.Length);

            BytesSent += encrypted.Length;
            LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: Send failed: {ex}");
            ConnectionException?.Invoke(this, ex);
        }
    }

    public void DatabaseStoreMessageReceived(DatabaseStoreMessage dsm)
    {
        // NTCP2 doesn't use DatabaseStore messages in handshake
        // Pass to higher layers if needed
    }

    public void Tick()
    {
        if (IsTerminated) return;

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (State != NTCP2SessionState.Established)
        {
            // Handshake timeout (30 seconds)
            if (now - LastActivityTime > 30)
            {
                Logging.LogInformation($"{DebugId}: Handshake timeout (30 seconds) in state {State}");
                Terminate($"Handshake timeout (30s, State: {State})");
            }

            return;
        }

        // Inactivity timeout (5 minutes)
        if (now - LastActivityTime > 300)
        {
            Logging.LogInformation($"{DebugId}: Inactivity timeout (5 minutes)");
            Terminate($"Inactivity timeout (5m, State: {State})");
        }

        // Keep-alive (DateTime block)
        KeepAlive.Do(() =>
        {
            if (IsTerminated) return;
            Logging.LogDebug($"{DebugId}: Sending keep-alive (DateTime block)");
            var frame = new NTCP2DataFrame();
            frame.AddBlock(new NTCP2DateTimeBlock());
            // Add some random padding to keep frame sizes varied
            frame.AddBlock(new NTCP2PaddingBlock(16 + BufUtils.RandomInt(48)));

            var encrypted = frame.BuildEncryptedFrame(NoiseState, SendSipHash);
            try
            {
                var stream = TcpClient.GetStream();
                stream.Write(encrypted, 0, encrypted.Length);
                BytesSent += encrypted.Length;
                LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"{DebugId}: Keep-alive send failed: {ex.Message}");
            }
        });

        // RouterInfo resend
        if (NextRouterInfoResendTime > 0 && now > NextRouterInfoResendTime) SendRouterInfo();
    }

    public void Terminate(string reason = null)
    {
        if (IsTerminated)
            return;

        var wasEstablished = State == NTCP2SessionState.Established;
        IsTerminated = true;
        State = NTCP2SessionState.Terminated;

        var logMsg = string.IsNullOrEmpty(reason) ? "Session terminated" : $"Session terminated: {reason}";
        Logging.LogDebug($"{DebugId}: {logMsg}");
        TransportConnectionLogger.Inst.Log(logMsg, RemoteRouterInfo?.Identity?.IdentHash?.Id64Short, "NTCP2",
            IsOutgoing ? "Outbound" : "Inbound", TcpClient?.Client?.RemoteEndPoint as IPEndPoint);

        if (!wasEstablished)
            TransportConnectionLogger.Inst.RecordFailure("NTCP2",
                IsOutgoing ? "Outbound" : "Inbound",
                reason ?? "Unknown",
                RemoteRouterInfo?.Identity?.IdentHash?.Id64Short,
                RemoteRouterInfo?.Identity?.IdentHash?.Id64,
                RemoteRouterInfo,
                TcpClient?.Client?.RemoteEndPoint as IPEndPoint);

        try
        {
            TcpClient?.Close();
        }
        catch
        {
        }

        ClearSensitiveData();

        ConnectionShutDown?.Invoke(this);
    }

    private void StartReceiveLoop()
    {
        Task.Run(async () =>
        {
            try
            {
                var stream = TcpClient.GetStream();
                var buffer = new byte[8192];

                // No socket-level read timeout — rely on Tick() inactivity detection (5 min)
                // and keep-alive sends (every 2 min) to handle unresponsive peers.
                // Must use -1 (Timeout.Infinite); 0 is invalid for NetworkStream.ReadTimeout.
                stream.ReadTimeout = Timeout.Infinite;

                Logging.LogDebug($"{DebugId}: Receive loop started, waiting for response...");

                while (!IsTerminated && TcpClient.Connected)
                {
                    int bytesRead;
                    try
                    {
                        bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    }
                    catch (IOException ex) when (ex.InnerException is SocketException socketEx &&
                                                 socketEx.SocketErrorCode == SocketError.TimedOut)
                    {
                        Logging.LogWarning($"{DebugId}: Read timeout, no response from remote - terminating");
                        Terminate($"Read timeout (State: {State})");
                        break;
                    }
                    catch (IOException ex)
                    {
                        Logging.LogWarning($"{DebugId}: Read I/O error: {ex.Message}");
                        Terminate($"Read I/O error (State: {State}): {ex.Message}");
                        break;
                    }

                    if (bytesRead == 0)
                    {
                        // Connection closed
                        Logging.LogDebug($"{DebugId}: Connection closed by remote (0 bytes read)");
                        Terminate($"EOF (State: {State})");
                        break;
                    }

                    BytesReceived += bytesRead;
                    LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                    // Log received data
                    var dataPreview = bytesRead <= 64
                        ? BitConverter.ToString(buffer, 0, bytesRead).Replace("-", " ")
                        : BitConverter.ToString(buffer, 0, 64).Replace("-", " ") + "...";

                    Logging.LogDebug($"{DebugId}: Received {bytesRead} bytes in state {State}: {dataPreview}");

                    // Process received data
                    var data = new byte[bytesRead];
                    Array.Copy(buffer, data, bytesRead);
                    ProcessReceivedData(data);
                }
            }
            catch (Exception ex)
            {
                Logging.LogWarning($"{DebugId}: Receive loop error: {ex.Message}");
                Terminate($"Receive loop error (State: {State}): {ex.Message}");
            }
        });
    }

    private I2PRouterAddress ExtractSelectedAddress()
    {
        // Find NTCP2 address in router info
        var ntcp2Address = RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
            a.TransportStyle == "NTCP2" && a.Options.Contains("host") &&
            (RouterContext.UseIpV6 || !IPAddress.TryParse(a.Options["host"], out var ip) ||
             ip.AddressFamily != AddressFamily.InterNetworkV6));

        if (ntcp2Address == null)
            throw new ArgumentException("No suitable NTCP2 address found in RouterInfo (IPv6 might be disabled)");

        return ntcp2Address;
    }

    private IPEndPoint GetEndpointFromAddress(I2PRouterAddress address)
    {
        var host = address.Options["host"];
        var port = int.Parse(address.Options["port"]);
        var ipAddress = IPAddress.Parse(host);

        return new IPEndPoint(ipAddress, port);
    }

    /// <summary>
    ///     Check if the remote peer supports ML-KEM post-quantum in NTCP2.
    ///     Returns version 3/4/5 for ML-KEM-512/768/1024, or 0 for no PQ.
    /// </summary>
    private int DetectRemotePQVersion()
    {
        if (RemoteRouterInfo == null) return 0;

        var bestVersion = 0;

        // 1. If we have a selected address, use its options first.
        if (SelectedAddress != null)
        {
            if (SelectedAddress.Options.Contains("pq") && int.TryParse(SelectedAddress.Options["pq"], out var pq))
                bestVersion = Math.Max(bestVersion, pq);
            if (SelectedAddress.Options.Contains("PQ") && int.TryParse(SelectedAddress.Options["PQ"], out var pq2))
                bestVersion = Math.Max(bestVersion, pq2);
            if (int.TryParse(SelectedAddress.Options["v"], out var version) && version >= 3 && version <= 5)
                bestVersion = Math.Max(bestVersion, version);
        }

        if (bestVersion > 0) return bestVersion;

        // 2. Fallback: check all NTCP2/NTCP addresses if no selected address or it had no PQ options.
        if (RemoteRouterInfo.Addresses != null)
            foreach (var addr in RemoteRouterInfo.Addresses)
                if ((addr.TransportStyle == "NTCP2" || addr.TransportStyle == "NTCP") && addr.Options.Contains("v"))
                {
                    // Standard: v=2 and pq=[3|4|5]
                    if (addr.Options.Contains("pq") && int.TryParse(addr.Options["pq"], out var pq))
                        bestVersion = Math.Max(bestVersion, pq);
                    if (addr.Options.Contains("PQ") && int.TryParse(addr.Options["PQ"], out var pq2))
                        bestVersion = Math.Max(bestVersion, pq2);

                    // Future: v=[3|4|5]
                    if (int.TryParse(addr.Options["v"], out var version) && version >= 3 && version <= 5)
                        bestVersion = Math.Max(bestVersion, version);
                }

        return bestVersion;
    }

    private void GenerateMLKEMKeyPair(int pqVersion)
    {
        switch (pqVersion)
        {
            case 3:
                (LocalKemPublicKey, LocalKemSecretKey) = MLKEM512.GenerateKeyPair();
                break;
            case 4:
                (LocalKemPublicKey, LocalKemSecretKey) = MLKEM768.GenerateKeyPair();
                break;
            case 5:
                (LocalKemPublicKey, LocalKemSecretKey) = MLKEM1024.GenerateKeyPair();
                break;
        }
    }

    private (byte[] ciphertext, byte[] sharedSecret) EncapsulateMLKEM(byte[] publicKey, int pqVersion)
    {
        return pqVersion switch
        {
            3 => MLKEM512.Encapsulate(publicKey),
            4 => MLKEM768.Encapsulate(publicKey),
            5 => MLKEM1024.Encapsulate(publicKey),
            _ => throw new ArgumentException($"Invalid PQ version: {pqVersion}")
        };
    }

    private byte[] DecapsulateMLKEM(byte[] ciphertext, byte[] secretKey, int pqVersion)
    {
        return pqVersion switch
        {
            3 => MLKEM512.Decapsulate(ciphertext, secretKey),
            4 => MLKEM768.Decapsulate(ciphertext, secretKey),
            5 => MLKEM1024.Decapsulate(ciphertext, secretKey),
            _ => throw new ArgumentException($"Invalid PQ version: {pqVersion}")
        };
    }

    private void InitializeNoiseAsAlice()
    {
        // Get Bob's static key from RouterInfo
        var bobStaticKey = GetRemoteStaticKey();

        // Check for PQ support: only use PQ if BOTH remote AND we support it.
        // i2pd rejects PQ sessions from routers without an ML-KEM crypto type
        // (see i2pd NTCP2.cpp ProcessSessionRequestMessage: m_CryptoType check).
        PQVersion = DetectRemotePQVersion();
        var ourPQVersion = Host.GetPreferredPQVersion();
        IsPQ = ourPQVersion >= 3 && PQVersion >= 3 && PQVersion <= 5;
        Logging.LogDebug(
            $"{DebugId}: InitializeNoiseAsAlice: remotePQVersion={PQVersion}, ourPQVersion={ourPQVersion}, IsPQSession={IsPQ}");

        var protocolName = NoiseXK.PROTOCOL_NAME_NTCP2;
        if (IsPQ)
            protocolName = PQVersion switch
            {
                3 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM512,
                4 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM768,
                5 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM1024,
                _ => NoiseXK.PROTOCOL_NAME_NTCP2
            };

        // Initialize Noise XK as Alice
        NoiseState = new NoiseXK(protocolName);

        // Use our persistent static keys from NTCP2Host (NOT random keys!)
        var alicePriv = Host.GetStaticPrivateKey();
        var alicePub = Host.GetStaticPublicKey();

        NoiseState.InitializeAsAlice(alicePriv, alicePub, bobStaticKey);
    }

    private byte[] GetRemoteStaticKey()
    {
        // Use selected address if available, otherwise fallback to FirstOrDefault
        var address = SelectedAddress ?? RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
            (a.TransportStyle == "NTCP2" || a.TransportStyle == "NTCP") && a.Options.Contains("s"));

        if (address == null || !address.Options.Contains("s"))
            throw new ArgumentException("No NTCP2 static key in RouterInfo");

        var base64Key = address.Options["s"];
        return FreenetBase64.Decode(base64Key);
    }

    private byte[] GetRemoteIV()
    {
        // Use selected address if available, otherwise fallback to FirstOrDefault
        var address = SelectedAddress ?? RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
            (a.TransportStyle == "NTCP2" || a.TransportStyle == "NTCP") && a.Options.Contains("i"));

        if (address == null || !address.Options.Contains("i"))
            throw new ArgumentException("No NTCP2 IV in RouterInfo");

        var base64IV = address.Options["i"];
        return FreenetBase64.Decode(base64IV);
    }

    private void SendSessionRequest()
    {
        // Build options block for SessionRequest payload
        // 0.9.69 allows up to 880 bytes for SessionRequest.
        // i2pd picks padding based on handshake size.
        // For PQ (ML-KEM-768), Message 1 is ~1264 bytes. 
        // We limit padding to 64 bytes to stay within MTU (1500) and avoid fragmentation.
        var rng = new Random();
        var paddingLen = rng.Next(0, 65);

        // NTCP2 Spec line 392: limit to 287 bytes total for NTCP style addresses.
        // (32 bytes X + 32 bytes encrypted options/MAC = 64 bytes)
        if (!IsPQ && RemoteRouterInfo?.Addresses.Any(a => a.TransportStyle == "NTCP") == true)
            paddingLen = Math.Min(paddingLen, 287 - 64);

        var payload = BuildRequestPayload(paddingLen);

        Logging.LogDebug(
            $"{DebugId}: Built SessionRequest payload: {BitConverter.ToString(payload).Replace("-", " ")}");

        // Get Bob's router hash and IV for AES obfuscation
        var bobRouterHash = RemoteRouterInfo.Identity.IdentHash.Hash.ToByteArray();
        var bobIV = GetRemoteIV();

        // DIAG: Log keys used to obfuscate (should match i2pd's DIAG-Bob log)
        var remoteStaticKey = GetRemoteStaticKey();
        Logging.LogInformation(
            $"{DebugId}: DIAG-Alice SendSR bobHash[0:4]={BitConverter.ToString(bobRouterHash, 0, 4).Replace("-", "")} bobIV[0:4]={BitConverter.ToString(bobIV, 0, 4).Replace("-", "")} bobS[0:4]={BitConverter.ToString(remoteStaticKey, 0, 4).Replace("-", "")} IsPQ={IsPQ}");

        // Generate ephemeral keys for Alice
        var ephKey = NoiseState.GenerateAliceEphemeralKeys();

        // Signal PQ via MSB of X (spec line 363 in ntcp2-hybrid.md)
        if (IsPQ) ephKey[31] |= 0x80;
        else ephKey[31] &= 0x7f;

        var obfuscatedKey = AESObfuscation.Encrypt(ephKey, bobRouterHash, bobIV);

        // Create message 1 with these keys
        byte[] encryptedPQFrame = null;
        byte[] encryptedPayload;

        if (IsPQ)
        {
            // Hybrid Handshake Message 1: -> e, es, e1, p
            var cipherKey = NoiseState.PerformMessage1EphemeralAndES();

            GenerateMLKEMKeyPair(PQVersion);
            encryptedPQFrame = NoiseState.EncryptHandshakeBlock(cipherKey, LocalKemPublicKey);

            // Payload (options) uses n=1
            encryptedPayload = NoiseState.EncryptHandshakeBlock(cipherKey, payload);
        }
        else
        {
            // Standard Handshake Message 1: -> e, es, p
            (var key, encryptedPayload) = NoiseState.CreateMessage1WithCurrentKeys(payload);
        }

        // Add padding
        var padding = paddingLen > 0 ? new byte[paddingLen] : Array.Empty<byte>();
        if (paddingLen > 0) rng.NextBytes(padding);

        // Per NTCP2 spec line 391: Alice SHOULD buffer and then flush Message 1 together
        var totalMsg1Size = obfuscatedKey.Length + (encryptedPQFrame?.Length ?? 0) + encryptedPayload.Length + paddingLen;
        var totalMsg1 = new byte[totalMsg1Size];
        var writer = new I2PBufferCursor(totalMsg1);

        writer.WriteBytes(obfuscatedKey);

        // Store AES state for Message 2 deobfuscation
        AESStateAfterMsg1 = new byte[16];
        Array.Copy(obfuscatedKey, 16, AESStateAfterMsg1, 0, 16);

        if (IsPQ && encryptedPQFrame != null) writer.WriteBytes(encryptedPQFrame);
        writer.WriteBytes(encryptedPayload);

        if (paddingLen > 0) writer.WriteBytes(padding);

        // Per NTCP2 spec lines 586-596: Alice must MixHash padding after sending Message 1
        NoiseState.MixHashPadding(padding);

        // Send to TCP stream
        var stream = TcpClient.GetStream();
        stream.Write(totalMsg1, 0, totalMsg1.Length);
        stream.Flush();

        BytesSent += totalMsg1.Length;

        Logging.LogInformation(
            $"{DebugId}: SessionRequest sent ({BytesSent} total bytes) to {TcpClient.Client.RemoteEndPoint}");
    }

    private byte[] BuildRequestPayload(int paddingLen)
    {
        // Build options block for SessionRequest
        var payload = new byte[16];
        var writer = new I2PBufferCursor(payload);

        // Per i2pd, timestamp is rounded to seconds with +500ms bias
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var timestamp = (uint)((nowMs + 500) / 1000);

        // Calculate m3p2len - the length of message 3 part 2 (encrypted)
        // Per NTCP2 spec and Java implementation:
        // Message 3 part 2 contains NTCP2 payload blocks:
        // 1. RouterInfo block: BLOCK_HEADER (3) + flood flag (1) + RouterInfo data
        // 2. Options block: BLOCK_HEADER (3) + options data (12)
        // 3. AEAD MAC (16 bytes)

        var myRouterInfo = Host.GetMyRouterInfo();
        var riStream = new ArrayBufferWriter<byte>();
        myRouterInfo.Write(riStream);
        CachedMyRouterInfoBytes = riStream.WrittenSpan.ToArray();

        // Calculate total payload size (including 16-byte MAC)
        // RI Format: type (1) + length (2) + flood flag (1) + RouterInfo data
        var totalPart2PayloadSize = 1 + 2 + 1 + CachedMyRouterInfoBytes.Length;

        // Options Format: type (1) + length (2) + options data (12)
        totalPart2PayloadSize += 1 + 2 + 12;

        // NTCP2 spec line 440: m3p2len is the length of message 3 part 2,
        // which includes the 16-byte MAC.
        CachedM3P2Len = (ushort)(totalPart2PayloadSize + 16);

        writer.WriteByte((byte)I2PConstants.I2PNetworkId); // NetworkId (byte 0)
        writer.WriteByte(2); // Version (byte 1)
        writer.WriteUInt16BigEndian((ushort)paddingLen); // Padding length (bytes 2-3)
        writer.WriteUInt16BigEndian(CachedM3P2Len); // m3p2len (bytes 4-5, 16-bit per i2pd)
        writer.WriteUInt16BigEndian(0); // Reserved (bytes 6-7)
        writer.WriteUInt32BigEndian(timestamp); // tsA (bytes 8-11)
        writer.WriteUInt32BigEndian(0); // Reserved (bytes 12-15)

        Logging.LogDebug(
            $"{DebugId}: BuildRequestPayload - NetworkId={I2PConstants.I2PNetworkId}, Version=2, PaddingLen={paddingLen}, m3p2len={CachedM3P2Len}, timestamp={timestamp}");

        return payload;
    }

    private void UpdateNextRouterInfoResendTime()
    {
        var random = new Random();
        NextRouterInfoResendTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() +
                                   1500 + random.Next(1500); // 25-50 minutes
    }

    public void SendRouterInfo()
    {
        if (State != NTCP2SessionState.Established) return;

        var myRouterInfo = Host.GetMyRouterInfo();
        if (myRouterInfo == null) return;

        // i2pd NTCP2.cpp SendRouterInfo() implementation:
        // 1. DateTime block
        // 2. RouterInfo block
        // 3. Padding block (optional but recommended)
        var frame = new NTCP2DataFrame();
        frame.AddBlock(new NTCP2DateTimeBlock());
        DateTimeBlockSent = true;

        // RouterInfo block (Type 2)
        byte flags = 0;
        if (RouterContext.Inst.FloodfillEnabled) flags |= 0x01; // bit 0: flood

        var riBlock = new NTCP2RouterInfoBlock { RouterInfo = myRouterInfo, Flags = flags };
        frame.AddBlock(riBlock);

        // Add some padding per i2pd: random length up to 32 bytes
        var random = new Random();
        frame.AddBlock(new NTCP2PaddingBlock(random.Next(32)));

        Logging.LogInformation($"{DebugId}: Sending RouterInfo as data frame");
        SendDataFrame(frame);

        // Update resend time
        UpdateNextRouterInfoResendTime();
    }

    private void SendDataFrame(NTCP2DataFrame dataFrame)
    {
        if (State != NTCP2SessionState.Established)
        {
            Logging.LogWarning($"{DebugId}: Cannot send data frame, session not established");
            return;
        }

        try
        {
            // Encrypt and build complete frame with SipHash obfuscation
            var frame = dataFrame.BuildEncryptedFrame(
                NoiseState,
                SendSipHash
            );

            // Send via TCP
            var stream = TcpClient.GetStream();
            if (stream != null && stream.CanWrite)
            {
                stream.Write(frame, 0, frame.Length);
                stream.Flush();
            }

            BytesSent += frame.Length;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: SendDataFrame failed: {ex}");
            ConnectionException?.Invoke(this, ex);
        }
    }

    private byte[] BuildDataFrame(I2NpMessage msg)
    {
        // Build NTCP2 data frame with I2NP message using NTCP2DataFrame
        // The first frame MUST contain a DateTime block
        var dataFrame = NTCP2DataFrame.BuildWithI2NPMessage(msg, !DateTimeBlockSent);
        DateTimeBlockSent = true;

        // Encrypt and build complete frame with SipHash obfuscation
        return dataFrame.BuildEncryptedFrame(
            NoiseState,
            SendSipHash
        );
    }

    public void ProcessReceivedData(byte[] data)
    {
        try
        {
            // Append to receive buffer
            Array.Copy(data, 0, ReceiveBuffer, ReceiveBufferPos, data.Length);
            ReceiveBufferPos += data.Length;

            bool processed;
            do
            {
                processed = false;
                var oldState = State;
                var oldPos = ReceiveBufferPos;

                switch (State)
                {
                    case NTCP2SessionState.Initial:
                        // Waiting for SessionRequest (obfuscated key + encrypted payload)
                        if (ReceiveBufferPos >= 32 + 32) // Min size: 32 key + 32 payload (options+MAC)
                        {
                            ProcessSessionRequest();
                        }
                        break;

                    case NTCP2SessionState.SessionRequestSent:
                        // Waiting for SessionCreated (obfuscated key + encrypted payload)
                        if (ReceiveBufferPos >= 32 + 32)
                        {
                            ProcessSessionCreated();
                        }
                        break;

                    case NTCP2SessionState.SessionCreatedSent:
                        // Waiting for SessionConfirmed (encrypted static key + encrypted payload)
                        if (ReceiveBufferPos >= 48 + 32) // 48 Part 1 + min 32 Part 2
                        {
                            ProcessSessionConfirmed();
                        }
                        break;

                    case NTCP2SessionState.Established:
                        // Data phase - process frames
                        ProcessDataFrames();
                        break;
                }

                // If state changed or data was consumed, try processing more from the buffer
                if (State != oldState || ReceiveBufferPos < oldPos)
                {
                    processed = true;
                }
            } while (processed && !IsTerminated && ReceiveBufferPos > 0);

            BytesReceived += data.Length;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: ProcessReceivedData failed: {ex}");
            ConnectionException?.Invoke(this, ex);
            Terminate($"ProcessReceivedData failed (State: {State}): {ex.Message}");
        }
    }

    private void ProcessSessionRequest()
    {
        if (ReceiveBufferPos < 32 + 32) // Minimum: 32-byte obfuscated X + 32-byte encrypted options
            return;

        // Deobfuscate ephemeral key with AES-256-CBC
        var ourRouterHash = Host.GetRouterHash(); // Our router's hash (32 bytes)
        var ourIV = Host.GetIV(); // Our published IV (16 bytes)

        var obfuscatedKey = new byte[32];
        Array.Copy(ReceiveBuffer, 0, obfuscatedKey, 0, 32);

        // DIAG: Log keys used for deobfuscation (should match i2pd's DIAG-Alice log)
        Logging.LogInformation(
            $"{DebugId}: DIAG-Bob ProcessSR ourHash[0:4]={BitConverter.ToString(ourRouterHash, 0, 4).Replace("-", "")} ourIV[0:4]={BitConverter.ToString(ourIV, 0, 4).Replace("-", "")} ourS[0:4]={BitConverter.ToString(Host.GetStaticPublicKey(), 0, 4).Replace("-", "")} rcvdBuf[0:4]={BitConverter.ToString(obfuscatedKey, 0, 4).Replace("-", "")}");

        if (!HandshakeDecrypted)
        {
            // Replay protection (spec line 505)
            if (!NTCP2SecurityValidator.CheckAndAddEncryptedToReplayCache(obfuscatedKey))
            {
                var msg = "SessionRequest replay detected";
                Logging.LogWarning(
                    $"{DebugId}: TERMINATION REASON [C#-BOB]: {msg} - same obfuscated key seen before (possible reconnect within 240s window)");
                Terminate(msg);
                return;
            }

            var ephemeralKey = AESObfuscation.Decrypt(obfuscatedKey, ourRouterHash, ourIV);

            // Store AES state for Message 2 obfuscation
            AESStateAfterMsg1 = new byte[16];
            Array.Copy(obfuscatedKey, 16, AESStateAfterMsg1, 0, 16);

            var isPQ = (ephemeralKey[31] & 0x80) != 0;

            // Only accept PQ if we support it and have a version published
            var ourPQVersion = Host.GetPreferredPQVersion();

            if (isPQ && ourPQVersion == 0)
            {
                var msg = "SessionRequest PQ bit set but PQ not supported by this host";
                Logging.LogWarning($"{DebugId}: TERMINATION REASON [C#-BOB]: {msg}");
                Terminate(msg);
                return;
            }

            var acceptPQ = isPQ;
            var pqKeyLen = 0;
            var payloadOffset = 32;
            var minSize = 64;

            if (acceptPQ)
            {
                // Bob (responder) uses his published version as the "Source of Truth".
                // initiators (Alice) MUST use the version published in Bob's RI.
                PQVersion = ourPQVersion;

                pqKeyLen = PQVersion switch
                {
                    3 => 800,
                    4 => 1184,
                    5 => 1568,
                    _ => 0
                };
                payloadOffset = 32 + pqKeyLen + 16;
                minSize = payloadOffset + 32;
            }

            if (ReceiveBufferPos < minSize)
            {
                // NEW: Opportunistic non-PQ trial (probing resistance for false PQ signals)
                if (acceptPQ && ReceiveBufferPos >= 64 && ReceiveBufferPos < 500)
                {
                    // Check if this might be a non-PQ message trapped by false bit 7
                    if (TryDecryptAsNonPQ(ephemeralKey))
                    {
                        Logging.LogInformation(
                            $"{DebugId}: False PQ detection (bit 7 set) resolved via opportunistic decryption. Proceeding as non-PQ.");
                        acceptPQ = false;
                        PQVersion = 0;
                        pqKeyLen = 0;
                        payloadOffset = 32;
                        minSize = 64;
                        // Continue processing with non-PQ settings
                    }
                    else
                    {
                        Logging.LogInformation(
                            $"{DebugId}: PQ detected in SessionRequest (bit 7 set), but only {ReceiveBufferPos} bytes in buffer. " +
                            $"Waiting for {minSize} bytes (PQVersion={PQVersion}).");
                        return;
                    }
                }
                else
                {
                    Logging.LogDebug($"{DebugId}: Waiting for more SessionRequest data (have {ReceiveBufferPos}/{minSize} bytes)");
                    return;
                }
            }

            // CRITICAL: Clear PQ signal bit (MSB) before Noise processing (spec line 363)
            // Java I2P and i2pd do NOT include the signal bit in Noise hashes.
            ephemeralKey[31] &= 0x7f;

            IsPQ = acceptPQ;
            // PQVersion already set by dynamic detection above if IsPQ is true.

            var protocolName = IsPQ
                ? PQVersion switch
                {
                    3 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM512,
                    4 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM768,
                    5 => NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM1024,
                    _ => NoiseXK.PROTOCOL_NAME_NTCP2
                }
                : NoiseXK.PROTOCOL_NAME_NTCP2;

            InitializeNoiseAsBob(protocolName);

            byte[] cipherKey = null;
            if (IsPQ)
            {
                cipherKey = NoiseState.PerformProcessMessage1EphemeralAndES(ephemeralKey);

                var encryptedPQFrame = new byte[pqKeyLen + 16];
                Array.Copy(ReceiveBuffer, 32, encryptedPQFrame, 0, encryptedPQFrame.Length);
                RemoteKemPublicKey = NoiseState.DecryptHandshakeBlock(cipherKey, encryptedPQFrame);
            }

            var encryptedPayloadWithMac = new byte[32];
            Array.Copy(ReceiveBuffer, payloadOffset, encryptedPayloadWithMac, 0, 32);

            if (IsPQ)
                HandshakeDecryptedOptions = NoiseState.DecryptHandshakeBlock(cipherKey, encryptedPayloadWithMac);
            else
                HandshakeDecryptedOptions = NoiseState.ProcessMessage1(ephemeralKey, encryptedPayloadWithMac);

            if (HandshakeDecryptedOptions == null)
            {
                var msg = "SessionRequest AEAD verification failed";
                Logging.LogWarning(
                    $"{DebugId}: TERMINATION REASON [C#-BOB]: {msg} - i2pd Alice used wrong Noise key (static key mismatch or wrong router hash/IV for AES deobfuscation)");
                Terminate(msg);
                return;
            }

            var readerOpts = new I2PBufferCursor(HandshakeDecryptedOptions);
            readerOpts.ReadByte(); // networkId
            readerOpts.ReadByte(); // version
            HandshakePaddingLen = readerOpts.ReadUInt16BigEndian();
            HandshakeDecrypted = true;
        }

        // Deobfuscation state was already handled if HandshakeDecrypted is true.
        // We need to re-derive payloadOffset to check for totalMsgSize.
        var pqKeyLenRecalc = IsPQ
            ? PQVersion switch
            {
                3 => 800,
                4 => 1184,
                5 => 1568,
                _ => 0
            }
            : 0;
        var payloadOffsetRecalc = 32 + (IsPQ ? pqKeyLenRecalc + 16 : 0);

        // Now we know HandshakePaddingLen
        var totalMsgSize = payloadOffsetRecalc + 32 + HandshakePaddingLen;
        if (ReceiveBufferPos < totalMsgSize)
        {
            Logging.LogDebug($"{DebugId}: Waiting for SessionRequest padding (have {ReceiveBufferPos}/{totalMsgSize} bytes)");
            return;
        }

        // Parse options from already decrypted payload
        var reader = new I2PBufferCursor(HandshakeDecryptedOptions);
        RemoteNetworkId = reader.ReadByte();
        RemoteVersion = reader.ReadByte();
        var paddingLen = reader.ReadUInt16BigEndian();
        var m3p2len = reader.ReadUInt16BigEndian();
        RemoteM3P2Len = m3p2len;

        // Spec line 876: part 2 max frame length is 65487
        if (m3p2len > 65487)
        {
            var msg = $"SessionRequest m3p2len={m3p2len} exceeds max";
            Logging.LogWarning(
                $"{DebugId}: TERMINATION REASON [C#-BOB]: {msg} 65487");
            Terminate(msg);
            return;
        }

        reader.ReadUInt16BigEndian(); // Reserved
        var timestamp = reader.ReadUInt32BigEndian();

        // Log options for debugging
        Logging.LogDebug(
            $"{DebugId}: SessionRequest options: networkId={RemoteNetworkId}, version={RemoteVersion}, paddingLen={paddingLen}, m3p2len={m3p2len}, timestamp={timestamp}");

        // Validate version (i2pd responder ignores networkId)
        if (RemoteVersion < 2)
        {
            var msg = $"SessionRequest invalid version={RemoteVersion}";
            Logging.LogWarning(
                $"{DebugId}: TERMINATION REASON [C#-BOB]: {msg} (expected >=2)");
            Terminate(msg);
            return;
        }

        // Validate padding length
        if (paddingLen > ReceiveBuffer.Length - payloadOffsetRecalc - 128)
        {
            var msg = $"SessionRequest excessive padding={paddingLen}";
            Logging.LogWarning(
                $"{DebugId}: TERMINATION REASON [C#-BOB]: {msg} (max {ReceiveBuffer.Length - payloadOffsetRecalc - 128})");
            Terminate(msg);
            return;
        }

        // Validate timestamp
        if (!NTCP2SecurityValidator.ValidateTimestamp(timestamp))
        {
            Logging.LogWarning($"{DebugId}: SessionRequest timestamp validation failed (Clock Skew)");
            // NTCP2 Spec line 1420: Bob should reply with SessionCreated even if skew is exceeded.
            // This allows Alice to calculate the skew.
            ClockSkewDetected = true;
        }

        // MixHash padding if present (spec lines 586-596)
        var paddingOffset = payloadOffsetRecalc + 32;
        if (ReceiveBufferPos < paddingOffset + paddingLen)
        {
            Logging.LogDebug(
                $"{DebugId}: Not enough data for padding ({ReceiveBufferPos}/{paddingOffset + paddingLen})");
            return; // Wait for more data
        }

        var padding = new byte[paddingLen];
        if (paddingLen > 0) Array.Copy(ReceiveBuffer, paddingOffset, padding, 0, paddingLen);
        NoiseState.MixHashPadding(padding);

        // Clear processed data from buffer
        var totalProcessed = paddingOffset + paddingLen; // X + PQ + payload + padding
        if (ReceiveBufferPos > totalProcessed)
        {
            var remaining = ReceiveBufferPos - totalProcessed;
            Array.Copy(ReceiveBuffer, totalProcessed, ReceiveBuffer, 0, remaining);
            ReceiveBufferPos = remaining;
        }
        else
        {
            ReceiveBufferPos = 0;
        }

        State = NTCP2SessionState.SessionRequestReceived;

        HandshakeDecrypted = false;
        HandshakeDecryptedOptions = null;
        HandshakePaddingLen = 0;

        Logging.LogDebug($"{DebugId}: SessionRequest received and validated");

        // Send SessionCreated
        SendSessionCreated();
    }

    /// <summary>
    ///     Tests if the first 64 bytes of ReceiveBuffer contain a valid non-PQ NTCP2 SessionRequest.
    ///     Used to recover from false-positive PQ signals (bit 7 set in decrypted ephemeral key).
    /// </summary>
    private bool TryDecryptAsNonPQ(byte[] ephemeralKey)
    {
        try
        {
            // Ephemeral key bit 7 must be cleared for Noise hash/DH
            var noiseKey = (byte[])ephemeralKey.Clone();
            noiseKey[31] &= 0x7f;

            // Use a temporary Noise state for probing
            var tempNoise = new NoiseXK(NoiseXK.PROTOCOL_NAME_NTCP2);
            tempNoise.InitializeAsBob(Host.GetStaticPrivateKey(), Host.GetStaticPublicKey());

            var payloadWithMac = new byte[32];
            Array.Copy(ReceiveBuffer, 32, payloadWithMac, 0, 32);

            // If AEAD verification fails, this returns null
            var options = tempNoise.ProcessMessage1(noiseKey, payloadWithMac);
            if (options != null)
            {
                Logging.LogDebug($"{DebugId}: TryDecryptAsNonPQ SUCCESS - bit 7 was indeed false positive.");
                return true;
            }

            Logging.LogDebug($"{DebugId}: TryDecryptAsNonPQ failed (AEAD mismatch). Bit 7 likely REAL PQ signal.");
            return false;
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"{DebugId}: TryDecryptAsNonPQ failed with exception: {ex.Message}");
            return false;
        }
    }

    private void ProcessSessionCreated()
    {
        // SessionCreated structure (NTCP2 spec lines 797-835):
        // - 32 bytes: Obfuscated ephemeral key Y
        // - (PQ ONLY) ML-KEM ciphertext frame (784/1104/1584 bytes)
        // - 32 bytes: AEAD encrypted payload (16 bytes options + 16 bytes MAC)
        // - 0-n bytes: Padding

        if (ReceiveBufferPos < 64) return;

        var pqCTLen = IsPQ
            ? PQVersion switch
            {
                3 => 768,
                4 => 1088,
                5 => 1568,
                _ => 0
            }
            : 0;

        var payloadOffset = 32 + (IsPQ ? pqCTLen + 16 : 0);
        var minSize = payloadOffset + 32;

        if (ReceiveBufferPos < minSize) return;

        if (!HandshakeDecrypted)
        {
            // Extract obfuscated ephemeral key Y
            var obfuscatedKey = new byte[32];
            Array.Copy(ReceiveBuffer, 0, obfuscatedKey, 0, 32);

            // Replay protection (spec line 818)
            if (!NTCP2SecurityValidator.CheckAndAddEncryptedToReplayCache(obfuscatedKey))
            {
                var msg = "SessionCreated replay detected";
                Logging.LogWarning($"{DebugId}: {msg} - terminating");
                Terminate(msg);
                return;
            }

            // Get Bob's router hash and IV for deobfuscation
            var bobRouterHash = RemoteRouterInfo.Identity.IdentHash.Hash.ToByteArray();

            // Deobfuscate ephemeral key Y with continued AES state (IV = last 16 bytes of X_obf)
            var ephemeralKey = AESObfuscation.Decrypt(obfuscatedKey, bobRouterHash, AESStateAfterMsg1);

            // CRITICAL: Java I2P (v0.9.69) DOES NOT set the PQ bit in Message 2 (responder).
            // Initiator must NOT rely on the signal bit in Y to determine hybrid status.
            // We already know we are in a hybrid session because we initiated it.
            ephemeralKey[31] &= 0x7f;

            byte[] cipherKey;
            if (IsPQ)
            {
                cipherKey = NoiseState.PerformProcessMessage2EphemeralAndEE(ephemeralKey);
                Logging.LogDebug($"{DebugId}: [PQ] Alice ProcessSC - cipherKey1 derived from ee");

                var encryptedPQFrame = new byte[pqCTLen + 16];
                Array.Copy(ReceiveBuffer, 32, encryptedPQFrame, 0, encryptedPQFrame.Length);
                var kemCiphertext = NoiseState.DecryptHandshakeBlock(cipherKey, encryptedPQFrame);
                Logging.LogDebug($"{DebugId}: [PQ] Alice ProcessSC - Decrypted kemCiphertext ({kemCiphertext.Length} bytes)");

                var sharedSecret = DecapsulateMLKEM(kemCiphertext, LocalKemSecretKey, PQVersion);
                cipherKey = NoiseState.MixKeyPQ(sharedSecret);
                NoiseState.StoreMessage2CipherKey(cipherKey);
                Logging.LogDebug($"{DebugId}: [PQ] Alice ProcessSC - cipherKey2 derived from ML-KEM");
            }
            else
            {
                cipherKey = null;
            }

            var encryptedPayload = new byte[32];
            Array.Copy(ReceiveBuffer, payloadOffset, encryptedPayload, 0, 32);

            try
            {
                if (IsPQ)
                    HandshakeDecryptedOptions = NoiseState.DecryptHandshakeBlock(cipherKey, encryptedPayload);
                else
                    HandshakeDecryptedOptions = NoiseState.ProcessMessage2(ephemeralKey, encryptedPayload);
            }
            catch (Exception ex)
            {
                var msg = $"SessionCreated AEAD verification failed: {ex.Message}";
                Logging.LogWarning($"{DebugId}: {msg}");
                Terminate(msg);
                return;
            }

            if (HandshakeDecryptedOptions == null || HandshakeDecryptedOptions.Length != 16)
            {
                var msg = "SessionCreated decryption failed - invalid options size";
                Logging.LogWarning($"{DebugId}: {msg}");
                Terminate(msg);
                return;
            }

            var readerOpts = new I2PBufferCursor(HandshakeDecryptedOptions);
            readerOpts.ReadUInt16BigEndian(); // Reserved (bytes 0-1)
            HandshakePaddingLen = readerOpts.ReadUInt16BigEndian(); // padLen (bytes 2-3)
            HandshakeDecrypted = true;
        }

        // Now we know HandshakePaddingLen
        var totalMsgSize = payloadOffset + 32 + HandshakePaddingLen;
        if (ReceiveBufferPos < totalMsgSize) return;

        // Parse options (16 bytes)
        var reader = new I2PBufferCursor(HandshakeDecryptedOptions);
        reader.ReadUInt16BigEndian(); // Reserved (bytes 0-1)
        var paddingLen = reader.ReadUInt16BigEndian(); // padLen (bytes 2-3)

        // Spec line 640: max padding is 848 bytes for SessionCreated
        // We relax this to fit our buffer
        if (paddingLen > ReceiveBuffer.Length - payloadOffset - 128)
        {
            Logging.LogWarning($"{DebugId}: SessionCreated padding length too large: {paddingLen}");
            Terminate("SessionCreated padding too large");
            return;
        }

        reader.ReadUInt32BigEndian(); // Reserved (bytes 4-7)
        var timestamp = reader.ReadUInt32BigEndian(); // tsB (bytes 8-11)
        reader.ReadUInt32BigEndian(); // Reserved (bytes 12-15)

        // Spec line 635: Alice must reject bad timestamp.
        if (!NTCP2SecurityValidator.ValidateTimestamp(timestamp))
        {
            Logging.LogWarning($"{DebugId}: SessionCreated timestamp validation failed (Clock Skew)");
            Terminate("SessionCreated clock skew");
            return;
        }

        // Alice MUST NOT update CachedM3P2Len based on Message 2.
        // Message 2 contains Reserved fields, not an echo of m3p2len.
        // Per 0.9.69 spec, Bob should not echo it here.
        // CachedM3P2Len remains what Alice sent in SessionRequest.

        // Padding handling
        var paddingOffset = payloadOffset + 32;
        if (ReceiveBufferPos < paddingOffset + paddingLen)
        {
            Logging.LogDebug($"{DebugId}: Waiting for padding ({ReceiveBufferPos}/{paddingOffset + paddingLen})");
            return; // Wait for more data
        }

        var padding = new byte[paddingLen];
        if (paddingLen > 0) Array.Copy(ReceiveBuffer, paddingOffset, padding, 0, paddingLen);
        NoiseState.MixHashPadding(padding);

        // Clear processed data from buffer
        var totalProcessed = paddingOffset + paddingLen;
        if (ReceiveBufferPos > totalProcessed)
        {
            var remaining = ReceiveBufferPos - totalProcessed;
            Array.Copy(ReceiveBuffer, totalProcessed, ReceiveBuffer, 0, remaining);
            ReceiveBufferPos = remaining;
        }
        else
        {
            ReceiveBufferPos = 0;
        }

        State = NTCP2SessionState.SessionCreatedReceived;

        HandshakeDecrypted = false;
        HandshakeDecryptedOptions = null;
        HandshakePaddingLen = 0;

        Logging.LogDebug($"{DebugId}: SessionCreated received and validated");

        // Send SessionConfirmed
        SendSessionConfirmed();
    }

    private void ProcessSessionConfirmed()
    {
        // SessionConfirmed structure:
        // - Part 1: 48 bytes (32 bytes encrypted static key + 16 bytes MAC)
        // - Part 2: RemoteM3P2Len (RI block + optional blocks + MAC)

        // Per i2pd, RemoteM3P2Len from options block ALREADY includes the 16-byte MAC.
        if (ReceiveBufferPos < 48 + RemoteM3P2Len)
        {
            Logging.LogDebug(
                $"{DebugId}: Waiting for more SessionConfirmed data ({ReceiveBufferPos}/{48 + RemoteM3P2Len} bytes)");
            return;
        }

        // Extract encrypted static key (Part 1: 48 bytes)
        var encryptedStaticKey = new byte[48];
        Array.Copy(ReceiveBuffer, 0, encryptedStaticKey, 0, 48);

        // Extract encrypted payload (Part 2: RemoteM3P2Len)
        var encryptedPayload = new byte[RemoteM3P2Len];
        Array.Copy(ReceiveBuffer, 48, encryptedPayload, 0, RemoteM3P2Len);

        // Process Noise message 3
        var staticKey = NoiseState.ProcessMessage3Part1(encryptedStaticKey);
        var payload = NoiseState.ProcessMessage3Part2(encryptedPayload);

        if (staticKey == null || payload == null)
        {
            var msg = "SessionConfirmed AEAD verification failed";
            Logging.LogWarning($"{DebugId}: {msg}");
            Terminate(msg);
            return;
        }

        // Get pre-Split CK/hash for SipHash key derivation (Bob side)
        PreSplitChainingKey = NoiseState.GetPreSplitChainingKey();
        PreSplitHash = NoiseState.GetPreSplitHash();

        // Parse payload to get RouterInfo and other blocks
        var reader = new I2PBufferCursor(payload);
        try
        {
            while (reader.Remaining >= 3)
            {
                var blockType = reader.ReadByte();
                var blockLen = reader.ReadUInt16BigEndian();

                if (reader.Remaining < blockLen)
                {
                    Logging.LogWarning(
                        $"{DebugId}: SessionConfirmed block length {blockLen} exceeds remaining payload {reader.Remaining}");
                    break;
                }

                var blockData = reader.ReadBytes(blockLen);

                switch ((NTCP2BlockType)blockType)
                {
                    case NTCP2BlockType.RouterInfo:
                        var floodFlag = blockData[0];
                        var riData = new byte[blockLen - 1];
                        Array.Copy(blockData, 1, riData, 0, blockLen - 1);
                        RemoteRouterInfo = new I2PRouterInfo(new I2PBufferCursor(riData), false);

                        // Verify Alice's static key matches (spec line 853)
                        var riStaticKey = RemoteRouterInfo.Addresses
                            .FirstOrDefault(a => a.Options.Contains("s"))
                            ?.Options["s"]?.ToString();

                        if (riStaticKey != null)
                        {
                            var riStaticKeyBytes = FreenetBase64.Decode(riStaticKey);
                            var match = true;
                            if (riStaticKeyBytes.Length == staticKey.Length)
                            {
                                for (var i = 0; i < staticKey.Length; i++)
                                    if (riStaticKeyBytes[i] != staticKey[i])
                                    {
                                        match = false;
                                        break;
                                    }
                            }
                            else
                            {
                                match = false;
                            }

                            if (!match)
                            {
                                Logging.LogWarning($"{DebugId}: Static key mismatch between Message 3 and RouterInfo");
                                Terminate("Static key mismatch");
                                return;
                            }
                        }

                        NetDb.Inst.AddRouterInfo(RemoteRouterInfo);
                        Logging.LogDebug(
                            $"{DebugId}: Received RouterInfo block in SessionConfirmed (flood={floodFlag})");
                        break;

                    case NTCP2BlockType.Options:
                        Logging.LogDebug($"{DebugId}: Received Options block in SessionConfirmed");
                        // We don't act on options for now, but we parse them
                        var opts = new NTCP2OptionsBlock();
                        opts.Parse(new I2PBufferCursor(blockData));
                        break;

                    case NTCP2BlockType.Padding:
                        Logging.LogDebug($"{DebugId}: Received Padding block in SessionConfirmed ({blockLen} bytes)");
                        break;

                    default:
                        Logging.LogInformation(
                            $"{DebugId}: Received unknown block type {blockType} in SessionConfirmed");
                        break;
                }
            }

            if (RemoteRouterInfo == null)
            {
                var msg = "SessionConfirmed did not contain RouterInfo";
                Logging.LogWarning($"{DebugId}: {msg}");
                Terminate(msg);
                return;
            }
        }
        catch (Exception ex)
        {
            var msg = $"Failed to parse SessionConfirmed blocks: {ex.Message}";
            Logging.LogWarning($"{DebugId}: {msg}");
            Terminate(msg);
            return;
        }

        // Clear processed data from buffer
        var totalProcessed = 48 + RemoteM3P2Len;
        if (ReceiveBufferPos > totalProcessed)
        {
            var remaining = ReceiveBufferPos - totalProcessed;
            Array.Copy(ReceiveBuffer, totalProcessed, ReceiveBuffer, 0, remaining);
            ReceiveBufferPos = remaining;
        }
        else
        {
            ReceiveBufferPos = 0;
        }

        if (ClockSkewDetected)
        {
            Logging.LogWarning($"{DebugId}: Session established but clock skew still exceeds limit. Terminating.");
            SendTermination(NTCP2TerminationReason.ClockSkew);
            Terminate("Clock skew exceeds limit");
            return;
        }

        State = NTCP2SessionState.Established;

        // Initialize SipHash keys for data phase
        InitializeSipHashKeys();
        UpdateNextRouterInfoResendTime();

        Logging.LogInformation($"{DebugId}: Session established with {RemoteRouterInfo?.Identity?.IdentHash}");
        TransportConnectionLogger.Inst.Log("Session established", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short,
            "NTCP2", IsOutgoing ? "Outbound" : "Inbound", TcpClient?.Client?.RemoteEndPoint as IPEndPoint);
        TransportConnectionLogger.Inst.RecordSuccess("NTCP2", IsOutgoing ? "Outbound" : "Inbound");

        // Fire ConnectionCreated event for incoming connection
        if (!IsOutgoing && RemoteRouterInfo?.Identity?.IdentHash != null)
            Host.FireConnectionCreated(this, RemoteRouterInfo.Identity.IdentHash);

        // Notify connection established
        ConnectionEstablished?.Invoke(this, RemoteRouterInfo?.Identity?.IdentHash);

        // Replicate i2pd behaviour: Bob sends his RouterInfo immediately after establishment
        // See i2pd NTCP2.cpp SendLocalRouterInfo and Transports.cpp PeerConnected.
        if (!IsOutgoing) SendRouterInfo();
    }

    private void ProcessDataFrames()
    {
        // Data phase - extract and process frames
        while (ReceiveBufferPos >= 2)
        {
            ushort frameLength;

            if (_pendingFrameLength.HasValue)
            {
                // We already deobfuscated this length but didn't have enough data
                frameLength = _pendingFrameLength.Value;
            }
            else
            {
                // Read and deobfuscate new length
                var obfuscatedLength = BitConverter.ToUInt16(ReceiveBuffer, 0);
                if (BitConverter.IsLittleEndian)
                    obfuscatedLength = (ushort)IPAddress.NetworkToHostOrder((short)obfuscatedLength);

                frameLength = ReceiveSipHash.DeobfuscateLength(obfuscatedLength);
                _pendingFrameLength = frameLength;
            }

            // Check if we have full frame
            if (ReceiveBufferPos < 2 + frameLength)
                break;

            // Extract frame data
            var frameData = new byte[frameLength];
            Array.Copy(ReceiveBuffer, 2, frameData, 0, frameLength);

            // Parse and process frame with AEAD error handling (spec lines 234-243)
            NTCP2DataFrame dataFrame;
            try
            {
                var reader = new I2PBufferCursor(frameData);
                dataFrame = NTCP2DataFrame.Parse(
                    reader,
                    NoiseState,
                    frameLength
                );
            }
            catch (Exception ex)
            {
                // AEAD failure in data phase (spec lines 234-243)
                Logging.LogWarning($"{DebugId}: Data phase AEAD failure: {ex.Message}");

                // Probing resistance: random delay + read
                if (TcpClient != null)
                {
                    var stream = TcpClient.GetStream();
                    var remoteAddress = RemoteAddress?.ToString() ?? "unknown";
                    NTCP2ProbingResistance.HandleAEADFailure(stream, remoteAddress, false);
                }

                // Send termination with DataPhaseAeadFailure reason
                SendTermination(NTCP2TerminationReason.DataPhaseAeadFailure);

                // Close connection
                Terminate($"Data phase AEAD failure: {ex.Message}");
                return;
            }

            // Process blocks
            foreach (var block in dataFrame.Blocks)
                switch (block.BlockType)
                {
                    case NTCP2BlockType.I2NP:
                        // Parse and deliver I2NP message
                        var header = block.ParseAsI2NPHeader();
                        if (header != null)
                        {
                            Logging.LogInformation(
                                $"{DebugId}: Received I2NP {header.MessageType} ({block.Data.Length} bytes)");
                            DataBlockReceived?.Invoke(this, header);
                        }

                        break;

                    case NTCP2BlockType.RouterInfo:
                        try
                        {
                            var riBlock = new NTCP2RouterInfoBlock();
                            riBlock.Parse(new I2PBufferCursor(block.Data));
                            if (riBlock.RouterInfo != null)
                            {
                                Logging.LogDebug(
                                    $"{DebugId}: Received RouterInfo block for {riBlock.RouterInfo.Identity.IdentHash}");
                                NetDb.Inst.AddRouterInfo(riBlock.RouterInfo);

                                // If this is our peer's RI, update our local record
                                if (RemoteRouterInfo != null &&
                                    RemoteRouterInfo.Identity.IdentHash == riBlock.RouterInfo.Identity.IdentHash)
                                    RemoteRouterInfo = riBlock.RouterInfo;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logging.LogWarning($"{DebugId}: Failed to parse RouterInfo block: {ex.Message}");
                        }

                        break;

                    case NTCP2BlockType.DateTime:
                        try
                        {
                            var dtBlock = new NTCP2DateTimeBlock();
                            dtBlock.Parse(new I2PBufferCursor(block.Data));
                            var now = (uint)((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 500) / 1000);
                            var skew = (long)now - dtBlock.Timestamp;

                            if (Math.Abs(skew) > 60)
                            {
                                Logging.LogWarning($"{DebugId}: Clock skew detected ({skew}s). Terminating session.");
                                SendTermination(NTCP2TerminationReason.ClockSkew);
                                Terminate("Clock skew detected");
                                return;
                            }

                            Logging.LogDebug($"{DebugId}: DateTime block received. Skew: {skew}s");
                        }
                        catch (Exception ex)
                        {
                            Logging.LogWarning($"{DebugId}: Failed to parse DateTime block: {ex.Message}");
                        }

                        break;

                    case NTCP2BlockType.Termination:
                        try
                        {
                            var termBlock = new NTCP2TerminationBlock();
                            termBlock.Parse(new I2PBufferCursor(block.Data));
                            Logging.LogInformation(
                                $"{DebugId}: Received termination block (reason={termBlock.Reason}, ValidPackets={termBlock.ValidPacketsReceived})");
                            Terminate($"Received termination block (reason={termBlock.Reason})");
                            return;
                        }
                        catch (Exception ex)
                        {
                            Logging.LogInformation(
                                $"{DebugId}: Received termination block (parse failed: {ex.Message})");
                            Terminate("Received malformed termination block");
                            return;
                        }

                    case NTCP2BlockType.Padding:
                        Logging.LogDebug($"{DebugId}: Received padding block ({block.Data.Length} bytes)");
                        break;

                    default:
                        Logging.LogDebug($"{DebugId}: Ignoring unknown block type {block.BlockType}");
                        break;
                }

            // Frame successfully processed - clear pending length
            _pendingFrameLength = null;

            // Remove processed frame from buffer
            var remainingBytes = ReceiveBufferPos - (2 + frameLength);
            if (remainingBytes > 0) Array.Copy(ReceiveBuffer, 2 + frameLength, ReceiveBuffer, 0, remainingBytes);
            ReceiveBufferPos = remainingBytes;
        }
    }

    private void InitializeNoiseAsBob(string protocolName)
    {
        // Initialize Noise XK as Bob (responder)
        NoiseState = new NoiseXK(protocolName);

        // Get our static keys from Host
        var bobPriv = Host.GetStaticPrivateKey();
        var bobPub = Host.GetStaticPublicKey();

        // DIAG: verify private key matches public key
        var derivedPub = X25519.GetPublicKey(bobPriv);
        var match = derivedPub.SequenceEqual(bobPub);
        Logging.LogInformation(
            $"{DebugId}: DIAG-KeyPairCheck: bobPub[0:4]={BitConverter.ToString(bobPub, 0, 4).Replace("-", "")} derivedPub[0:4]={BitConverter.ToString(derivedPub, 0, 4).Replace("-", "")} match={match}");

        NoiseState.InitializeAsBob(bobPriv, bobPub);
    }

    private void SendSessionCreated()
    {
        // Choose a small random padding length (0-64)
        var rng = new Random();
        var paddingLen = rng.Next(0, 65);

        var payload = BuildSessionCreatedPayload(paddingLen);

        Logging.LogInformation(
            $"{DebugId}: Sending SessionCreated (Bob -> Alice): IsPQ={IsPQ}, paddingLen={paddingLen}, timestamp={((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 500) / 1000)}");

        // Get Bob's router hash
        var ourRouterHash = Host.GetRouterHash();

        // Generate ephemeral keys for Bob
        byte[] ephKey = NoiseState.GenerateBobEphemeralKeys();

        // Signal PQ via MSB of Y (spec line 363 in ntcp2-hybrid.md)
        // CRITICAL: Java I2P (v0.9.69) ONLY sets the PQ bit in Message 1 (Alice -> Bob).
        // Bob (responder) MUST NOT set it in Message 2 (Bob -> Alice), otherwise Alice's Noise hash will diverge.
        ephKey[31] &= 0x7f;

        var obfuscatedKey = AESObfuscation.Encrypt(ephKey, ourRouterHash, AESStateAfterMsg1);

        byte[] encryptedPQFrame = null;
        byte[] encryptedPayload;

        if (IsPQ)
        {
            // Hybrid Handshake Message 2: <- e, ee, ekem1, p
            var cipherKey = NoiseState.PerformMessage2EphemeralAndEE(IsPQ);
            Logging.LogDebug($"{DebugId}: [PQ] Bob SendSC - cipherKey1 derived from ee");

            var (ciphertext, sharedSecret) = EncapsulateMLKEM(RemoteKemPublicKey, PQVersion);
            encryptedPQFrame = NoiseState.EncryptHandshakeBlock(cipherKey, ciphertext);
            Logging.LogDebug($"{DebugId}: [PQ] Bob SendSC - Encrypted ML-KEM ciphertext ({ciphertext.Length} bytes)");

            // MixKey(kem_shared_key) - This also resets nonce for options
            var newCipherKey = NoiseState.MixKeyPQ(sharedSecret);
            NoiseState.StoreMessage2CipherKey(newCipherKey);
            Logging.LogDebug($"{DebugId}: [PQ] Bob SendSC - newCipherKey derived from ML-KEM");

            // Payload (options) uses n=0 (reset by MixKeyPQ)
            encryptedPayload = NoiseState.EncryptHandshakeBlock(newCipherKey, payload);
        }
        else
        {
            // Standard Handshake Message 2: <- e, ee, p
            (_, encryptedPayload) = NoiseState.CreateMessage2WithCurrentKeys(payload);
        }

        // Add optional padding - must match paddingLen in options block
        var padding = paddingLen > 0 ? new byte[paddingLen] : Array.Empty<byte>();
        if (paddingLen > 0) rng.NextBytes(padding);

        // Build complete message 2: obfuscated Y + encrypted payload + padding
        // Per NTCP2 spec line 611: Bob MUST buffer and then flush the entire contents
        var totalLen = obfuscatedKey.Length + (encryptedPQFrame?.Length ?? 0) + encryptedPayload.Length + paddingLen;
        var totalMsg2 = new byte[totalLen];
        var writer = new I2PBufferCursor(totalMsg2);

        writer.WriteBytes(obfuscatedKey);
        if (IsPQ && encryptedPQFrame != null) writer.WriteBytes(encryptedPQFrame);
        writer.WriteBytes(encryptedPayload);
        if (paddingLen > 0) writer.WriteBytes(padding);

        // Per NTCP2 spec lines 829-835: Bob must MixHash padding after sending Message 2
        NoiseState.MixHashPadding(padding);
        Logging.LogDebug($"{DebugId}: MixHashed Message 2 padding ({paddingLen} bytes)");

        // Send to TCP stream
        var stream = TcpClient.GetStream();
        stream.Write(totalMsg2, 0, totalMsg2.Length);
        stream.Flush();

        BytesSent += totalMsg2.Length;

        State = NTCP2SessionState.SessionCreatedSent;

        Logging.LogInformation($"{DebugId}: SessionCreated sent ({totalMsg2.Length} bytes) to {TcpClient.Client.RemoteEndPoint}");
    }

    private void SendSessionConfirmed()
    {
        // Build complete message 3
        var part2Payload = BuildMessage3Part2Payload();
        var encryptedPart1 = NoiseState.CreateMessage3Part1();
        var encryptedPart2 = NoiseState.CreateMessage3Part2(part2Payload);

        // Per NTCP2 spec line 863: Alice MUST buffer and then flush both frames together
        var totalMsg3 = new byte[encryptedPart1.Length + encryptedPart2.Length];
        Buffer.BlockCopy(encryptedPart1, 0, totalMsg3, 0, encryptedPart1.Length);
        Buffer.BlockCopy(encryptedPart2, 0, totalMsg3, encryptedPart1.Length, encryptedPart2.Length);

        // Get the CK and hash saved inside CreateMessage3Part2 right before Split()
        // cleared the CK. These are needed for SipHash key derivation.
        PreSplitChainingKey = NoiseState.GetPreSplitChainingKey();
        PreSplitHash = NoiseState.GetPreSplitHash();

        // Send to TCP stream
        var stream = TcpClient.GetStream();
        stream.Write(totalMsg3, 0, totalMsg3.Length);
        stream.Flush();

        BytesSent += totalMsg3.Length;

        Logging.LogDebug(
            $"{DebugId}: SessionConfirmed sent: part1={encryptedPart1.Length}B, part2={encryptedPart2.Length}B, totalMsg3={totalMsg3.Length}B, promisedM3P2Len={CachedM3P2Len}");

        State = NTCP2SessionState.Established;

        // Initialize SipHash keys for data phase using the pre-Split CK
        InitializeSipHashKeys();
        UpdateNextRouterInfoResendTime();

        Logging.LogDebug($"{DebugId}: SessionConfirmed sent");
        Logging.LogInformation($"{DebugId}: Session established");
        TransportConnectionLogger.Inst.RecordSuccess("NTCP2", "Outbound");

        // Send RouterInfo as first data frame for peer database update
        SendRouterInfo();

        // Notify connection established
        ConnectionEstablished?.Invoke(this, RemoteRouterInfo?.Identity?.IdentHash);
    }

    private byte[] BuildMessage3Part2Payload()
    {
        // Message 3 part 2 MUST contain:
        // - RouterInfo block (Type 2)
        // - Options block (Type 1)
        // And SHOULD contain:
        // - Padding block (Type 254)

        // Use cached RouterInfo bytes if available
        var routerInfoBytes = CachedMyRouterInfoBytes;
        if (routerInfoBytes == null)
        {
            var myRouterInfo = Host.GetMyRouterInfo();
            var riStream = new ArrayBufferWriter<byte>();
            myRouterInfo.Write(riStream);
            routerInfoBytes = riStream.WrittenSpan.ToArray();
        }

        // Options block (12 bytes fixed part)
        var optionsBlock = new NTCP2OptionsBlock();
        var optionsBytes = optionsBlock.Serialize();

        // Calculate how much space we have in Message 3 Part 2.
        // CachedM3P2Len includes the 16-byte MAC.
        var availableSize = CachedM3P2Len - 16;
        var requiredSize = 1 + 2 + 1 + routerInfoBytes.Length + 1 + 2 + optionsBytes.Length;

        var paddingSize = 0;
        if (availableSize > requiredSize)
        {
            // We have room for padding. Must be at least 3 bytes for the block header.
            if (availableSize - requiredSize >= 3)
                paddingSize = availableSize - requiredSize - 3;
            else
                // Too small for a padding block, but we MUST match CachedM3P2Len.
                // This should not happen if CachedM3P2Len was calculated correctly.
                Logging.LogWarning(
                    $"{DebugId}: M3P2 available size ({availableSize}) is slightly larger than required ({requiredSize}) but too small for padding block header.");
        }

        var payload = new byte[availableSize];
        var writer = new I2PBufferCursor(payload);

        // RouterInfo block
        writer.WriteByte((byte)NTCP2BlockType.RouterInfo);
        writer.WriteUInt16BigEndian((ushort)(1 + routerInfoBytes.Length)); // Length: flood flag + RI

        byte flags = 0;
        if (RouterContext.Inst.FloodfillEnabled) flags |= 0x01; // bit 0: flood
        writer.WriteByte(flags);
        writer.WriteBytes(routerInfoBytes);

        // Options block
        writer.WriteByte((byte)NTCP2BlockType.Options);
        writer.WriteUInt16BigEndian((ushort)optionsBytes.Length);
        writer.WriteBytes(optionsBytes);

        // Padding block if needed
        if (availableSize > requiredSize && availableSize - requiredSize >= 3)
        {
            writer.WriteByte((byte)NTCP2BlockType.Padding);
            writer.WriteUInt16BigEndian((ushort)paddingSize);
            if (paddingSize > 0)
            {
                var padding = new byte[paddingSize];
                new Random().NextBytes(padding);
                writer.WriteBytes(padding);
            }
        }

        Logging.LogDebug($"{DebugId}: Built message 3 part 2 payload: " +
                         $"RI block ({1 + routerInfoBytes.Length} bytes, flood={flags}), " +
                         $"Options block ({optionsBytes.Length} bytes), " +
                         $"Padding block ({paddingSize} bytes), " +
                         $"Total payload: {payload.Length} bytes (will be {payload.Length + 16} with MAC)");

        return payload;
    }

    private byte[] BuildSessionCreatedPayload(int paddingLen)
    {
        // NTCP2 spec lines 617-621 (accurate for 0.9.69):
        // Row 1: 2 bytes Rsvd (0), 2 bytes padLen, 4 bytes Reserved (0)
        // Row 2: 4 bytes tsB, 4 bytes Reserved (0)
        // Total: 16 bytes. Note: NO echoed networkId, version or m3p2len here.
        var payload = new byte[16];
        var writer = new I2PBufferCursor(payload);

        // Per i2pd/Java I2P, timestamp is rounded to seconds with +500ms bias
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var timestamp = (uint)((nowMs + 500) / 1000);

        writer.WriteUInt16BigEndian(0); // Rsvd (0)
        writer.WriteUInt16BigEndian((ushort)paddingLen); // padLen
        writer.WriteUInt32BigEndian(0); // Reserved (0)
        writer.WriteUInt32BigEndian(timestamp); // tsB
        writer.WriteUInt32BigEndian(0); // Reserved (0)

        return payload;
    }

    private void InitializeSipHashKeys()
    {
        // Derive SipHash keys according to NTCP2 spec (lines 1094-1160)
        // Use pre-Split CK/hash if available (Alice side saves them before Split clears CK).
        // For Bob side, the CK is still intact when this is called.
        var chainingKey = PreSplitChainingKey ?? NoiseState.GetChainingKey();
        var handshakeHash = PreSplitHash ?? NoiseState.GetHandshakeHash();

        var sipHashKeys = NTCP2KDF.DeriveSipHashKeys(chainingKey, handshakeHash);

        // Alice is the initiator, Bob is the responder
        if (IsOutgoing)
        {
            // We are Alice - use Alice to Bob keys for sending
            SendSipHash = new NTCP2SipHash(sipHashKeys.AliceToBobK1, sipHashKeys.AliceToBobK2,
                sipHashKeys.AliceToBobIV);
            // Use Bob to Alice keys for receiving
            ReceiveSipHash = new NTCP2SipHash(sipHashKeys.BobToAliceK1, sipHashKeys.BobToAliceK2,
                sipHashKeys.BobToAliceIV);
        }
        else
        {
            // We are Bob - use Bob to Alice keys for sending
            SendSipHash = new NTCP2SipHash(sipHashKeys.BobToAliceK1, sipHashKeys.BobToAliceK2,
                sipHashKeys.BobToAliceIV);
            // Use Alice to Bob keys for receiving
            ReceiveSipHash = new NTCP2SipHash(sipHashKeys.AliceToBobK1, sipHashKeys.AliceToBobK2,
                sipHashKeys.AliceToBobIV);
        }
    }

    private void SendTermination(NTCP2TerminationReason reason, byte[] additionalData = null)
    {
        try
        {
            if (NoiseState == null || State < NTCP2SessionState.Established || TcpClient == null)
                // Can't send termination before data phase
                return;

            // Build termination block (spec lines 1458-1490)
            var block = new NTCP2TerminationBlock
            {
                Reason = reason,
                AdditionalData = additionalData ?? Array.Empty<byte>()
            };

            // Serialize block
            var blockData = block.Serialize();

            // Create DataFrame with termination block
            var frame = new NTCP2DataFrame();
            frame.Blocks.Add(new NTCP2BlockWrapper
            {
                BlockType = NTCP2BlockType.Termination,
                Data = blockData
            });

            // Serialize frame
            var frameBytes = frame.ToByteArray();

            // Encrypt frame
            var encryptedFrame = NoiseState.EncryptData(frameBytes);

            // Obfuscate length
            var frameLength = (ushort)encryptedFrame.Length;
            var obfuscatedLength = SendSipHash.ObfuscateLength(frameLength);

            // Build complete frame: obfuscated length + encrypted payload
            var completeFrame = new byte[2 + encryptedFrame.Length];
            completeFrame[0] = (byte)(obfuscatedLength >> 8);
            completeFrame[1] = (byte)(obfuscatedLength & 0xFF);
            Array.Copy(encryptedFrame, 0, completeFrame, 2, encryptedFrame.Length);

            // Send
            var stream = TcpClient.GetStream();
            if (stream != null && stream.CanWrite)
            {
                stream.Write(completeFrame, 0, completeFrame.Length);
                stream.Flush();
            }

            Logging.LogDebug($"{DebugId}: Sent termination with reason {reason}");
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"{DebugId}: Failed to send termination: {ex.Message}");
        }
    }

    private void ClearSensitiveData()
    {
        // Zero out all sensitive key material
        NoiseState?.Clear();
    }
}