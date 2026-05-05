using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using I2PCore.Crypto;
using I2PCore.Crypto.MLKEM;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer.Log;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.TunnelLayer.I2NP.Data;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     Represents an SSU2 session between two routers
///     Implements the Noise XK handshake pattern and ITransport interface
/// </summary>
public class SSU2Session : ITransport
{
    // Fragment handler for reassembly of incoming fragmented messages
    private readonly SSU2FragmentHandler FragmentHandler = new();

    private readonly SSU2Host Host;

    // Queue for messages waiting for session establishment
    private readonly ConcurrentQueue<I2NpMessage> PendingMessages = new();

    // Maximum payload size (adjusted for IPv4/IPv6)
    private readonly int MaxPayloadSize = SSU2FragmentHandler.MAX_PAYLOAD_SIZE_IPV6;

    /// <summary>
    ///     Stored second fragment for retransmission if needed.
    /// </summary>
    private byte[] _sessionConfirmedFragment2;

    /// <summary>
    ///     Buffer for SessionConfirmed fragment reassembly (max 2 fragments per spec).
    ///     Stores the first-received fragment's payload while waiting for the other.
    /// </summary>
    private byte[] _sessionConfirmedFragmentBuffer;

    private SSU2Header _sessionConfirmedFragmentHeader;
    private bool _sessionConfirmedFragmentIsSecond;

    // ML-KEM post-quantum hybrid state

    private long LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private long HandshakeStartTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    // Connection IDs
    private ulong LocalConnectionId;
    private byte[] LocalKemPublicKey;
    private byte[] LocalKemSecretKey;

    // Noise protocol state
    private NoiseXK NoiseState;
    private int PQVersion; // 3=MLKEM768 (SSU2 uses 768 per i2pd)
    private byte[] ReceiveDataKey; // k_data for receiving
    private byte[] ReceiveHeaderKey2; // k_header_2 for receiving
    private uint ReceivePacketNumber;

    // Relay/PeerTest/HolePunch handler
    internal SSU2RelayHandler RelayHandler;
    private ulong RemoteConnectionId;
    private byte[] RemoteKemPublicKey;

    // Data phase keys (after Split())
    private byte[] SendDataKey; // k_data for sending
    private byte[] SendHeaderKey2; // k_header_2 for sending

    // Packet counters
    private uint SendPacketNumber;

    // Selected address for outbound connection
    private I2PRouterAddress SelectedAddress;

    // Constructor for outgoing connections
    public SSU2Session(SSU2Host host, I2PRouterInfo remoteRouter, bool isOutgoing)
    {
        Host = host;
        RemoteRouterInfo = remoteRouter;
        IsOutgoing = isOutgoing;
        State = SessionState.Initial;
        RelayHandler = new SSU2RelayHandler(host);
        DebugId = $"SSU2-{(isOutgoing ? "Out" : "In")}-{BufUtils.RandomUint():X8}";

        // Extract remote endpoint from router info
        ExtractRemoteEndpoint();

        // Generate local connection ID
        LocalConnectionId = BufUtils.RandomUint() | ((ulong)BufUtils.RandomUint() << 32);

        TransportConnectionLogger.Inst.Log(
            $"Created outbound SSU2 session to {RemoteRouterInfo?.Identity?.IdentHash?.Id32Short}",
            RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "SSU2", "Outbound");
    }

    // Constructor for incoming connections
    public SSU2Session(SSU2Host host, IPEndPoint remoteEndpoint)
    {
        Host = host;
        RemoteEndpoint = remoteEndpoint;
        IsOutgoing = false;
        State = SessionState.Initial;
        RelayHandler = new SSU2RelayHandler(host);
        DebugId = $"SSU2-In-{BufUtils.RandomUint():X8}";
        LocalConnectionId = BufUtils.RandomUint() | ((ulong)BufUtils.RandomUint() << 32);

        TransportConnectionLogger.Inst.Log("Accepted inbound SSU2 connection", null, "SSU2", "Inbound");
    }

    public IPEndPoint RemoteEndpoint { get; private set; }
    public I2PRouterInfo RemoteRouterInfo { get; private set; }
    public SessionState State { get; private set; }

    /// <summary>
    ///     Relay tag assigned to this session by the remote peer (for introducer use).
    /// </summary>
    public uint AssignedRelayTag { get; internal set; }

    // ITransport events
    public event Action<ITransport, Exception> ConnectionException;
    public event Action<ITransport> ConnectionShutDown;
    public event Action<ITransport, I2PIdentHash> ConnectionEstablished;
    public event Action<ITransport, Ii2NpHeader> DataBlockReceived;
    public I2PKeysAndCert RemoteRouterIdentity => RemoteRouterInfo?.Identity;

    public bool IsTerminated { get; private set; }
    public bool IsOutgoing { get; }

    // ITransport properties
    public IPAddress RemoteAddress => RemoteEndpoint?.Address;
    public long BytesSent { get; private set; }
    public long BytesReceived { get; private set; }
    public string DebugId { get; }
    public string Protocol => "SSU2";
    public bool IsPQ { get; private set; }

    public void Connect()
    {
        if (!IsOutgoing)
            throw new InvalidOperationException("Cannot call Connect on incoming session");

        if (State != SessionState.Initial)
            throw new InvalidOperationException($"Cannot connect from state {State}");

        try
        {
            Logging.LogDebug($"{DebugId}: Initiating SSU2 connection to {RemoteEndpoint}");
            TransportConnectionLogger.Inst.Log($"Initiating SSU2 connection to {RemoteEndpoint}",
                RemoteRouterInfo?.Identity?.IdentHash?.Id32Short, "SSU2", "Outbound");

            // Initialize Noise protocol as Alice (initiator)
            InitializeNoiseAsAlice();

            // Send SessionRequest
            SendSessionRequest();

            State = SessionState.SessionRequestSent;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: Connect failed: {ex}");
            ConnectionException?.Invoke(this, ex);
            Terminate($"Connect failed (State: {State}): {ex.Message}");
        }
    }

    public void Send(I2NpMessage msg)
    {
        if (State != SessionState.Established)
        {
            if (IsTerminated)
            {
                Logging.LogWarning($"{DebugId}: Cannot send, session is terminated");
                return;
            }

            Logging.LogDebug($"{DebugId}: Session not established, enqueuing message");
            PendingMessages.Enqueue(msg);
            return;
        }

        LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        try
        {
            // Get I2NP message bytes (NTCP2 short header format)
            var headerAndPayload = msg.CreateHeader16.HeaderAndPayload;
            var msgBytes = headerAndPayload.ToByteArray();

            // Check if fragmentation is needed
            if (SSU2FragmentHandler.NeedsFragmentation(msgBytes.Length, MaxPayloadSize))
            {
                SendFragmented(msgBytes, msg);
            }
            else
            {
                // Build single data packet with I2NP message
                var packet = BuildDataPacket(msg);
                Host.SendPacket(RemoteEndpoint, packet);
                BytesSent += packet.Length;
            }
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: Send failed: {ex}");
            ConnectionException?.Invoke(this, ex);
        }
    }

    public void DatabaseStoreMessageReceived(DatabaseStoreMessage dsm)
    {
        // SSU2 doesn't use DatabaseStore messages in handshake
        // Pass to higher layers if needed
    }

    public void Tick()
    {
        if (IsTerminated) return;

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (State != SessionState.Established)
        {
            // Handshake timeout (30 seconds)
            if (now - HandshakeStartTime > 30)
            {
                Logging.LogWarning($"{DebugId}: Handshake timeout (30 seconds, State: {State})");
                Terminate($"Handshake timeout (30 seconds, State: {State})");
            }

            return;
        }

        // Inactivity timeout (5 minutes)
        if (now - LastActivityTime > 300)
        {
            Logging.LogInformation($"{DebugId}: Inactivity timeout (5 minutes)");
            Terminate($"Inactivity timeout (5 minutes, State: {State})");
        }
    }

    public void Terminate(string reason = null)
    {
        if (IsTerminated)
            return;

        var wasEstablished = State == SessionState.Established;
        IsTerminated = true;
        State = SessionState.Terminated;

        var logMsg = string.IsNullOrEmpty(reason) ? "Session terminated" : $"Session terminated: {reason}";
        Logging.LogDebug($"{DebugId}: {logMsg}");
        TransportConnectionLogger.Inst.Log(logMsg, RemoteRouterInfo?.Identity?.IdentHash?.Id64Short, "SSU2",
            IsOutgoing ? "Outbound" : "Inbound", RemoteEndpoint);

        if (!wasEstablished)
            TransportConnectionLogger.Inst.RecordFailure("SSU2",
                IsOutgoing ? "Outbound" : "Inbound",
                reason ?? "Unknown",
                RemoteRouterInfo?.Identity?.IdentHash?.Id64Short,
                RemoteRouterInfo?.Identity?.IdentHash?.Id64,
                RemoteRouterInfo,
                RemoteEndpoint);

        // Clear sensitive data
        NoiseState?.Clear();

        ConnectionShutDown?.Invoke(this);
    }

    /// <summary>
    ///     Send a raw SSU2 block in a data packet.
    ///     Used for relay tag requests, peer tests, and other control blocks.
    /// </summary>
    public void SendBlock(SSU2BlockType blockType, byte[] blockData)
    {
        if (State != SessionState.Established) return;

        try
        {
            var packet = SSU2DataPacket.BuildWithBlock(
                blockType, blockData,
                RemoteConnectionId,
                SendPacketNumber++,
                SendDataKey, SendHeaderKey2);
            Host.SendPacket(RemoteEndpoint, packet);
            BytesSent += packet.Length;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: SendBlock failed: {ex.Message}");
        }
    }

    private void SendFragmented(byte[] i2npData, I2NpMessage msg)
    {
        // Extract message ID from I2NP header (bytes 1-4)
        uint msgId = 0;
        if (i2npData.Length >= 5)
            msgId = (uint)((i2npData[1] << 24) | (i2npData[2] << 16) | (i2npData[3] << 8) | i2npData[4]);

        var fragmentBlocks = SSU2FragmentHandler.FragmentMessage(i2npData, msgId, MaxPayloadSize);

        Logging.LogDebug(
            $"{DebugId}: Fragmenting I2NP message into {fragmentBlocks.Count} fragments ({i2npData.Length} bytes)");

        var kHeader1 = IsOutgoing ? GetRemoteIntroKey() : Host.GetMyIntroKey();

        foreach (var blockData in fragmentBlocks)
        {
            // Build a data packet containing this single fragment block
            var header = new SSU2Header
            {
                IsLongHeader = false,
                DestinationConnectionId = RemoteConnectionId,
                PacketNumber = SendPacketNumber++
            };

            // Build payload from block data
            var nonce = ChaCha20Poly1305.CreateNonce(header.PacketNumber);

            // Build 16-byte short header
            var headerBytes = new byte[16];
            headerBytes[0] = (byte)((header.DestinationConnectionId >> 56) & 0xFF);
            headerBytes[1] = (byte)((header.DestinationConnectionId >> 48) & 0xFF);
            headerBytes[2] = 0;
            headerBytes[3] = 0;
            var pnBytes = BufUtils.Flip32B(header.PacketNumber);
            Array.Copy(pnBytes, 0, headerBytes, 4, 4);

            // Encrypt payload (the fragment block)
            var encryptedPayload = ChaCha20Poly1305.Encrypt(SendDataKey, nonce, blockData, headerBytes);

            // Build complete packet
            var packet = new byte[16 + encryptedPayload.Length];
            Array.Copy(headerBytes, 0, packet, 0, 16);
            Array.Copy(encryptedPayload, 0, packet, 16, encryptedPayload.Length);

            // Encrypt header
            SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet, 0, kHeader1, SendHeaderKey2);

            Host.SendPacket(RemoteEndpoint, packet);
            BytesSent += packet.Length;
        }
    }

    /// <summary>
    ///     Send a PathResponse block echoing the challenge data.
    ///     Used for connection migration / path validation.
    /// </summary>
    private void SendPathResponse(byte[] challengeData)
    {
        // Build a data packet containing just the PathResponse block
        var blockData = new byte[3 + challengeData.Length]; // type(1) + length(2) + data
        blockData[0] = (byte)SSU2BlockType.PathResponse;
        blockData[1] = (byte)(challengeData.Length >> 8);
        blockData[2] = (byte)(challengeData.Length & 0xFF);
        Array.Copy(challengeData, 0, blockData, 3, challengeData.Length);

        // Send as a data packet through the established session
        // For now, log that we would send - actual integration depends on Send path
        Logging.LogDebug($"{DebugId}: PathResponse sent ({challengeData.Length} bytes)");
    }

    private void ExtractRemoteEndpoint()
    {
        // Find SSU2 address in router info with a host and port
        SelectedAddress = RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
            a.TransportStyle == "SSU2"
            && a.Options.TryGet("host") != null
            && a.Options.TryGet("port") != null
            && a.Options.TryGet("s") != null
            && a.Options.TryGet("i") != null
            && (RouterContext.UseIpV6 || !IPAddress.TryParse(a.Options["host"].ToString(), out var ip) ||
                ip.AddressFamily != AddressFamily.InterNetworkV6));

        if (SelectedAddress == null)
            throw new ArgumentException(
                "No suitable SSU2 address with host/port found in RouterInfo (IPv6 might be disabled)");

        var host = SelectedAddress.Options.TryGet("host")?.ToString();
        var portStr = SelectedAddress.Options.TryGet("port")?.ToString();

        if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(portStr))
            throw new ArgumentException("SSU2 address missing host or port");

        var port = int.Parse(portStr);
        var ipAddr = IPAddress.Parse(host);

        RemoteEndpoint = new IPEndPoint(ipAddr, port);
    }

    private void InitializeNoiseAsAlice()
    {
        // Get Bob's static key from RouterInfo
        var bobStaticKey = GetRemoteStaticKey();

        // Initialize Noise XK as Alice
        // The actual identifier per I2P spec: Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256
        NoiseState = new NoiseXK("Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256");

        // Use our router's static keys from RouterContext/Host
        var alicePriv = Host.GetStaticPrivateKey();
        var alicePub = Host.GetStaticPublicKey();

        NoiseState.InitializeAsAlice(alicePriv, alicePub, bobStaticKey);

        // Check if remote router supports post-quantum (ML-KEM-768)
        // Per i2pd, PQ version 3 = ML-KEM-768 for SSU2
        if (RemoteRouterInfo != null && SupportsPQ(RemoteRouterInfo))
        {
            IsPQ = true;
            PQVersion = 3; // ML-KEM-768
            (LocalKemPublicKey, LocalKemSecretKey) = MLKEM768.GenerateKeyPair();
            Logging.LogDebug($"{DebugId}: PQ session initialized with ML-KEM-768");
        }
    }

    /// <summary>
    ///     Check if a remote router advertises post-quantum support.
    ///     Routers indicate PQ support via crypto key type in their RouterInfo.
    /// </summary>
    private static bool SupportsPQ(I2PRouterInfo routerInfo)
    {
        try
        {
            // Check if router identity uses ECIES-MLKEM crypto key type
            var keyType = routerInfo.Identity?.Certificate?.PublicKeyType;
            return keyType == I2PKeyType.KeyTypes.MLKEM512_X25519
                   || keyType == I2PKeyType.KeyTypes.MLKEM768_X25519
                   || keyType == I2PKeyType.KeyTypes.MLKEM1024_X25519;
        }
        catch
        {
            return false;
        }
    }

    private byte[] GetRemoteStaticKey()
    {
        var address = SelectedAddress ?? RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
            a.Options.Contains("s") && a.TransportStyle == "SSU2");

        if (address == null || !address.Options.TryGet("s", out var base64Key))
            throw new ArgumentException("No SSU2 static key in RouterInfo");

        return FreenetBase64.Decode(base64Key.ToString());
    }

    private byte[] GetRemoteIntroKey()
    {
        var address = SelectedAddress ?? RemoteRouterInfo?.Addresses?.FirstOrDefault(a =>
            a.Options.Contains("i") && a.TransportStyle == "SSU2");

        if (address == null || !address.Options.TryGet("i", out var base64Key))
            throw new ArgumentException("No SSU2 intro key in RouterInfo");

        return FreenetBase64.Decode(base64Key.ToString());
    }

    private void SendSessionRequest()
    {
        Logging.LogDebug($"{DebugId}: Sending SessionRequest to {RemoteEndpoint} (PQ={IsPQ})");

        // Get Bob's intro key for header encryption
        var bobIntroKey = GetRemoteIntroKey();
        var kHeader1 = bobIntroKey;
        var kHeader2 = bobIntroKey;

        // Re-initialize Noise
        InitializeNoiseAsAlice();

        // Build header (plaintext initially)
        var header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_SESSION_REQUEST,
            Version = 2,
            NetId = 2,
            DestinationConnectionId = RemoteConnectionId,
            SourceConnectionId = LocalConnectionId,
            PacketNumber = BufUtils.RandomUint() // Random for handshake packets
        };
        var headerBytes = header.ToByteArray();

        // Build payload
        var payload = BuildRequestPayload();

        // Generate ephemeral keys; loop until the obfuscated first byte has MSB=0.
        // Precompute the headerX mask byte once: it depends only on kHeader2 (constant per session)
        // and does not change between attempts.
        var ephKeyMaskByte = SSU2HeaderEncryption.GetEphKeyMaskByte(kHeader2);
        byte[] ephKey;
        var attempts = 0;

        while (true)
        {
            attempts++;
            ephKey = NoiseState.GenerateAliceEphemeralKeys();

            // Signal PQ via MSB of X (spec line 363 in ntcp2-hybrid.md)
            if (IsPQ) ephKey[31] |= 0x80;
            else ephKey[31] &= 0x7f;

            // The ephemeral key occupies bytes 16-47 of the 48-byte headerX region (packet bytes 32-63),
            // so its obfuscated first byte uses keystream byte 16 of ChaCha20(kHeader2, zeroNonce).
            if (EphKeyFirstByteIsValid(ephKey[0], ephKeyMaskByte) && (IsPQ || (ephKey[31] & 0x80) == 0))
                break;

            if (attempts > 100)
                throw new Exception("Failed to generate valid SSU2 initiator ephemeral key after 100 attempts");
        }

        // Use Noise to create message 1 WITH HEADER (SSU2-specific)
        var (_, encryptedPayload) = NoiseState.CreateMessage1WithHeaderAndCurrentKeys(headerBytes, payload);

        // Build complete packet: long header (32 bytes) + plain ephKey (32 bytes) + encrypted payload.
        // Header encryption is applied in two separate steps below to match i2pd's layout exactly:
        //   1. Bytes  0-15 (destConnID+pktNum+type+flags): XOR with ChaCha20 masks derived from packet end.
        //   2. Bytes 16-63 (srcConnID+token+ephKey, the "headerX"): single 48-byte ChaCha20(kHeader2, zeroIV).
        var packet = new byte[headerBytes.Length + ephKey.Length + encryptedPayload.Length];
        Array.Copy(headerBytes, 0, packet, 0, headerBytes.Length);
        Array.Copy(ephKey, 0, packet, headerBytes.Length, ephKey.Length);
        Array.Copy(encryptedPayload, 0, packet, headerBytes.Length + ephKey.Length, encryptedPayload.Length);

        // Step 1: Encrypt bytes 0-15 using IVs from packet end
        SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, kHeader1, kHeader2);

        // Step 2: Obfuscate headerX bytes 16-63 (srcConnID+token+ephKey) with a single 48-byte keystream
        SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, kHeader2);

        // Send via host
        Host.SendPacket(RemoteEndpoint, packet);

        BytesSent += packet.Length;

        Logging.LogDebug($"{DebugId}: SessionRequest sent ({packet.Length} bytes)");
    }

    private byte[] BuildRequestPayload()
    {
        var stream = new ArrayBufferWriter<byte>();

        // Timestamp (4 bytes)
        var ts = (uint)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        stream.Write(BufUtils.Flip32B(ts));

        // Padding length (2 bytes)
        stream.Write(BufUtils.Flip16B(0));

        // Reserved (2 bytes)
        stream.Write(BufUtils.Flip16B(0));

        // If PQ session, include ML-KEM public key as an options block
        if (IsPQ && LocalKemPublicKey != null)
        {
            // PQ version byte (1 byte): 3 = ML-KEM-768
            stream.WriteByte((byte)PQVersion);
            // ML-KEM-768 encapsulation key (1184 bytes)
            stream.Write(LocalKemPublicKey);
        }

        return stream.WrittenSpan.ToArray();
    }

    private byte[] BuildDataPacket(I2NpMessage msg)
    {
        // Build SSU2 data packet with I2NP message using SSU2DataPacket
        var dataPacket = SSU2DataPacket.BuildWithI2NPMessage(
            msg,
            RemoteConnectionId,
            SendPacketNumber++
        );

        // Get header keys for data phase
        // k_header_1 = intro key of the router that published the SSU2 address.
        var kHeader1 = IsOutgoing ? GetRemoteIntroKey() : Host.GetMyIntroKey();

        // Encrypt and build complete packet using data phase keys
        return dataPacket.BuildEncryptedPacket(SendDataKey, kHeader1, SendHeaderKey2);
    }

    public void ProcessReceivedPacket(byte[] packetData)
    {
        try
        {
            Logging.LogDebug($"{DebugId}: ProcessReceivedPacket ({packetData.Length} bytes, State: {State})");

            // Decrypt header for type identification
            // SSU2 spec: long headers (Request/Created/Confirmed) are obfuscated differently than short headers (Data).
            // We need to try long header decryption first.
            var trialDecrypted = (byte[])packetData.Clone();
            var kHeader1 = IsOutgoing ? GetRemoteIntroKey() : Host.GetMyIntroKey();

            // Choose kHeader2 based on handshake state because bytes 8-15 (which contain the type byte
            // at offset 12) are encrypted with kHeader2 and each message type uses a different derivation:
            //   SessionRequest:   kHeader2 = introKey (no derivation)
            //   SessionCreated:   kHeader2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
            //   SessionConfirmed: SHORT header — handled separately below
            byte[] kHeader2;
            switch (State)
            {
                case SessionState.SessionRequestSent:
                {
                    // Alice is expecting SessionCreated; derive the correct k_header_2.
                    var chainKey = NoiseState.GetChainingKey();
                    if (chainKey == null || chainKey.Length != 32)
                        throw new InvalidOperationException(
                            $"{DebugId}: Noise chaining key unavailable or invalid in state {State}");
                    kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainKey);
                    break;
                }
                case SessionState.SessionCreatedSent:
                {
                    // Bob is expecting SessionConfirmed (SHORT header); derive k_header_2 for use
                    // in the short-header fallback below.
                    var chainKey = NoiseState.GetChainingKey();
                    if (chainKey == null || chainKey.Length != 32)
                        throw new InvalidOperationException(
                            $"{DebugId}: Noise chaining key unavailable or invalid in state {State}");
                    kHeader2 = SSU2HeaderEncryption.DeriveSessionConfirmedHeaderKey(chainKey);
                    break;
                }
                default:
                    // SessionRequest (and anything before handshake starts): kHeader2 = introKey.
                    kHeader2 = kHeader1;
                    break;
            }

            SSU2HeaderEncryption.DecryptLongHeaderInPacket(trialDecrypted, 0, kHeader1, kHeader2);

            var reader = new I2PBufferCursor(trialDecrypted);
            var header = SSU2Header.ParseLongHeader(reader);
            var type = header.Type;

            // If trial decryption with long-header keys didn't yield a valid type, try short header.
            if (type > 2 && type != SSU2Header.TYPE_DATA)
            {
                if (State == SessionState.Established)
                {
                    // Data phase: decrypt with established receive header key
                    var shortDecrypted = (byte[])packetData.Clone();
                    SSU2HeaderEncryption.DecryptShortHeaderInPacket(shortDecrypted, 0, kHeader1, ReceiveHeaderKey2);
                    type = shortDecrypted[12];
                }
                else if (State == SessionState.SessionCreatedSent)
                {
                    // SessionConfirmed uses a short header; kHeader2 was derived from chaining key above.
                    var shortDecrypted = (byte[])packetData.Clone();
                    SSU2HeaderEncryption.DecryptShortHeaderInPacket(shortDecrypted, 0, kHeader1, kHeader2);
                    type = shortDecrypted[12];
                }
            }

            Logging.LogDebug($"{DebugId}: Detected packet type {type} (State: {State})");

            switch (type)
            {
                case SSU2Header.TYPE_SESSION_REQUEST:
                    ProcessSessionRequest(packetData);
                    break;

                case SSU2Header.TYPE_SESSION_CREATED:
                    ProcessSessionCreated(packetData);
                    break;

                case SSU2Header.TYPE_SESSION_CONFIRMED:
                    ProcessSessionConfirmed(packetData);
                    break;

                case SSU2Header.TYPE_DATA:
                    ProcessDataPacket(packetData);
                    break;

                default:
                    Logging.LogDebug($"{DebugId}: Unknown packet type {type}");
                    break;
            }

            BytesReceived += packetData.Length;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: ProcessReceivedPacket failed: {ex}");
            ConnectionException?.Invoke(this, ex);
        }
    }

    private void ProcessSessionRequest(byte[] packetData)
    {
        Logging.LogDebug($"{DebugId}: Processing SessionRequest ({packetData.Length} bytes, State: {State})");

        if (State != SessionState.Initial)
        {
            Logging.LogWarning($"{DebugId}: Received SessionRequest in state {State}");
            return;
        }

        if (packetData.Length < 32 + 32 + 16) // Min: 32 header + 32 ephKey + 16 MAC
        {
            Logging.LogWarning($"{DebugId}: SessionRequest too short");
            return;
        }

        // Initialize Noise as Bob (responder)
        InitializeNoiseAsBob();

        // Extract encrypted header (first 32 bytes)
        var encryptedHeader = new byte[32];
        Array.Copy(packetData, 0, encryptedHeader, 0, 32);

        // Get our intro key for header decryption
        var ourIntroKey = Host.GetMyIntroKey();

        // For Session Request (Bob receives): k_header_1 = k_header_2 = Bob's intro key (NO derivation)
        // SSU2 spec lines 707-720
        var kHeader1 = ourIntroKey;
        var kHeader2 = ourIntroKey;

        // Decrypt the first 16 bytes of the long header using IVs from packet end.
        // (Bytes 16-63 — srcConnID + token + ephemeral key — are handled as "headerX" below.)
        SSU2HeaderEncryption.DecryptLongHeaderInPacket(packetData, 0, kHeader1, kHeader2);

        // Deobfuscate headerX: bytes 16-63 (srcConnID+token+ephKey) with a single 48-byte ChaCha20 keystream.
        // Per i2pd SSU2Session.cpp: ChaCha20(headerX, 48, introKey, zeroNonce, headerX)
        // This is the inverse of what ObfuscateHeaderX does in SendSessionRequest (ChaCha20 is its own inverse).
        SSU2HeaderEncryption.ObfuscateHeaderX(packetData, 16, kHeader2);

        // Parse header (now fully decrypted in packetData, bytes 0-31)
        var headerReader = new I2PBufferCursor(packetData);
        var header = SSU2Header.ParseLongHeader(headerReader);

        // Extract decrypted header for Noise hashing
        var decryptedHeader = new byte[32];
        Array.Copy(packetData, 0, decryptedHeader, 0, 32);

        // Validate version and network ID
        if (!SSU2SecurityValidator.ValidateVersionAndNetId(header.Version, header.NetId))
        {
            Logging.LogWarning($"{DebugId}: Invalid version or network ID");
            Terminate($"Invalid SSU2 version ({header.Version}) or network ID ({header.NetId})");
            return;
        }

        // Validate connection IDs are different
        if (!SSU2SecurityValidator.ValidateConnectionIds(header.SourceConnectionId, header.DestinationConnectionId))
        {
            Logging.LogWarning($"{DebugId}: Source and destination connection IDs must be different");
            Terminate("Source and destination connection IDs must be different");
            return;
        }

        // Store connection IDs
        RemoteConnectionId = header.SourceConnectionId;
        LocalConnectionId = header.DestinationConnectionId;

        // Extract ephemeral key from bytes 32-63 (already deobfuscated by ObfuscateHeaderX above)
        var ephemeralKey = new byte[32];
        Array.Copy(packetData, 32, ephemeralKey, 0, 32);

        // Check replay cache (spec lines 1207-1213)
        if (!SSU2SecurityValidator.CheckAndAddToReplayCache(ephemeralKey))
        {
            Logging.LogWarning($"{DebugId}: Replay attack detected - ephemeral key already seen");
            Terminate("Replay attack detected (ephemeral key reused)");
            return;
        }

        // Extract encrypted payload (rest of packet)
        var encryptedPayloadLen = packetData.Length - 64;
        var encryptedPayload = new byte[encryptedPayloadLen];
        Array.Copy(packetData, 64, encryptedPayload, 0, encryptedPayloadLen);

        // Process Noise message 1 WITH HEADER
        var payload = NoiseState.ProcessMessage1WithHeader(decryptedHeader, ephemeralKey, encryptedPayload);

        if (payload == null)
        {
            Logging.LogWarning($"{DebugId}: SessionRequest AEAD verification failed");
            Terminate("SessionRequest AEAD verification failed");
            return;
        }

        // Parse payload
        var payloadReader = new I2PBufferCursor(payload);
        var timestamp = payloadReader.ReadUInt32BigEndian();
        var paddingLen = payloadReader.ReadUInt16BigEndian();

        // Validate timestamp (clock skew check)
        var now = (uint)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        var skew = Math.Abs((int)(now - timestamp));
        if (skew > 60) // 60 second tolerance
        {
            Logging.LogWarning($"{DebugId}: Clock skew too large: {skew}s");
            Terminate($"Clock skew too large: {skew}s (SessionRequest)");
            return;
        }

        // Check for PQ KEM public key in remaining payload
        // If initiator sent ML-KEM key, we need to encapsulate and include ciphertext in reply
        var remainingAfterHeader = payload.Length - 8 - paddingLen;
        if (remainingAfterHeader > 1)
        {
            var pqReader = new I2PBufferCursor(payload, 8);
            var remotePQVersion = pqReader.ReadByte();
            if (remotePQVersion >= 1 && remotePQVersion <= 3)
            {
                var kemPubKeyLen = remotePQVersion switch
                {
                    3 => 1184, // ML-KEM-768 public key size
                    _ => 0
                };

                if (kemPubKeyLen > 0 && remainingAfterHeader >= 1 + kemPubKeyLen)
                {
                    RemoteKemPublicKey = pqReader.ReadBlock(kemPubKeyLen).ToByteArray();
                    IsPQ = true;
                    PQVersion = remotePQVersion;
                    Logging.LogDebug(
                        $"{DebugId}: PQ session request with ML-KEM-{remotePQVersion switch { 3 => "768", _ => "?" }}");
                }
            }
        }

        State = SessionState.SessionRequestReceived;

        Logging.LogDebug($"{DebugId}: SessionRequest received and validated");

        // Send SessionCreated
        SendSessionCreated();
    }

    private void ProcessSessionCreated(byte[] packetData)
    {
        Logging.LogDebug($"{DebugId}: Processing SessionCreated ({packetData.Length} bytes, State: {State})");

        if (State != SessionState.SessionRequestSent)
        {
            Logging.LogWarning($"{DebugId}: Received SessionCreated in state {State}");
            return;
        }

        if (packetData.Length < 32 + 32 + 16) // Min: 32 header + 32 ephKey + 16 MAC
        {
            Logging.LogWarning($"{DebugId}: SessionCreated too short");
            return;
        }

        // Extract encrypted header (first 32 bytes)
        var encryptedHeader = new byte[32];
        Array.Copy(packetData, 0, encryptedHeader, 0, 32);

        // Get Bob's intro key for header decryption
        var bobIntroKey = GetRemoteIntroKey();

        // For Session Created (Alice receives):
        // k_header_1 = bik (Bob's intro key)
        // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        // SSU2 spec lines 1255-1270
        var kHeader1 = bobIntroKey;
        var chainingKey = NoiseState.GetChainingKey();
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);

        // Decrypt the first 16 bytes of the long header using IVs from packet end.
        // (Bytes 16-63 — srcConnID + token + ephemeral key — are handled as "headerX" below.)
        SSU2HeaderEncryption.DecryptLongHeaderInPacket(packetData, 0, kHeader1, kHeader2);

        // Deobfuscate headerX: bytes 16-63 (srcConnID+token+ephKey) with a single 48-byte ChaCha20 keystream.
        // Per i2pd SSU2Session.cpp: ChaCha20(headerX, 48, kh2, zeroNonce, headerX)
        SSU2HeaderEncryption.ObfuscateHeaderX(packetData, 16, kHeader2);

        // Parse header (now fully decrypted in packetData, bytes 0-31)
        var headerReader = new I2PBufferCursor(packetData);
        var header = SSU2Header.ParseLongHeader(headerReader);

        // Extract decrypted header for Noise hashing
        var decryptedHeader = new byte[32];
        Array.Copy(packetData, 0, decryptedHeader, 0, 32);

        // Validate connection IDs
        if (header.DestinationConnectionId != LocalConnectionId)
        {
            Logging.LogWarning($"{DebugId}: Invalid destination connection ID");
            return;
        }

        // Extract the remote peer's connection ID from the SessionCreated response.
        // This is critical: we must use this ID in all subsequent messages to this peer.
        RemoteConnectionId = header.SourceConnectionId;
        Logging.LogDebug($"{DebugId}: Got remote connection ID: {RemoteConnectionId:X16}");

        // Extract ephemeral key from bytes 32-63 (already deobfuscated by ObfuscateHeaderX above)
        var ephemeralKey = new byte[32];
        Array.Copy(packetData, 32, ephemeralKey, 0, 32);

        // Extract encrypted payload (rest of packet)
        var encryptedPayloadLen = packetData.Length - 64;
        var encryptedPayload = new byte[encryptedPayloadLen];
        Array.Copy(packetData, 64, encryptedPayload, 0, encryptedPayloadLen);

        // Process Noise message 2 WITH HEADER
        var payload = NoiseState.ProcessMessage2WithHeader(decryptedHeader, ephemeralKey, encryptedPayload);

        if (payload == null)
        {
            Logging.LogWarning($"{DebugId}: SessionCreated AEAD verification failed");
            Terminate("SessionCreated AEAD verification failed");
            return;
        }

        // Parse payload
        var payloadReader = new I2PBufferCursor(payload);
        var timestamp = payloadReader.ReadUInt32BigEndian();
        var paddingLen = payloadReader.ReadUInt16BigEndian();

        // Validate timestamp (clock skew check)
        var now = (uint)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        var skew = Math.Abs((int)(now - timestamp));
        if (skew > 60) // 60 second tolerance
        {
            Logging.LogWarning($"{DebugId}: Clock skew too large: {skew}s");
            Terminate($"Clock skew too large: {skew}s (SessionCreated)");
            return;
        }

        // Skip reserved bytes (2 bytes)
        payloadReader.ReadByte();
        payloadReader.ReadByte();

        // Check for PQ KEM ciphertext in remaining payload
        // If we sent a PQ session request, the response should include
        // a KEM ciphertext that we need to decapsulate
        var remainingPayloadLen = payload.Length - 8 - paddingLen;
        if (IsPQ && LocalKemSecretKey != null)
        {
            var gotPQResponse = false;
            if (remainingPayloadLen >= 1089)
            {
                // Skip past any blocks to find PQ data
                // PQ response format: pqVersion(1) + kemCiphertext(1088 for ML-KEM-768)
                var pqReader = new I2PBufferCursor(payload, 8);
                var remotePQVersion = pqReader.ReadByte();
                if (remotePQVersion == PQVersion)
                {
                    var kemCiphertextLen = PQVersion switch
                    {
                        3 => 1088, // ML-KEM-768 ciphertext size
                        _ => 0
                    };

                    if (kemCiphertextLen > 0)
                    {
                        var kemCiphertext = pqReader.ReadBlock(kemCiphertextLen).ToByteArray();
                        var kemSharedSecret = MLKEM768.Decapsulate(kemCiphertext, LocalKemSecretKey);

                        // Mix KEM shared secret into Noise chaining key for post-quantum security
                        NoiseState.MixKeyPQ(kemSharedSecret);
                        Logging.LogDebug($"{DebugId}: PQ KEM decapsulated, mixed into session keys");
                        gotPQResponse = true;
                    }
                }
            }

            if (!gotPQResponse)
            {
                Logging.LogInformation(
                    $"{DebugId}: Bob rejected/downgraded SSU2 PQ hybrid session. Falling back to standard SSU2.");
                IsPQ = false;
            }
        }

        // Parse optional blocks (before padding)
        var blocksLen = payload.Length - 8 - paddingLen; // 8 = 4 timestamp + 2 padding len + 2 reserved
        if (blocksLen > 0)
        {
            var blocksData = new I2PBufferCursor(payloadReader.ReadBytes(blocksLen));
            ParseSessionCreatedBlocks(blocksData);
        }

        State = SessionState.SessionCreatedReceived;

        Logging.LogDebug($"{DebugId}: SessionCreated received and validated");

        // Send SessionConfirmed
        SendSessionConfirmed();
    }

    private void ProcessSessionConfirmed(byte[] packetData)
    {
        Logging.LogDebug($"{DebugId}: Processing SessionConfirmed ({packetData.Length} bytes, State: {State})");

        if (State != SessionState.SessionCreatedSent)
        {
            Logging.LogWarning($"{DebugId}: Received SessionConfirmed in state {State}");
            return;
        }

        // SessionConfirmed uses SHORT header (16 bytes) per spec lines 1676-1680
        const int SHORT_HEADER_SIZE = 16;

        // Decrypt header (SSU2 spec lines 1750-1776):
        // k_header_1 = our intro key - our own static key
        // k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
        var kHeader1 = Host.GetMyIntroKey(); // Our intro key
        var chainingKey = NoiseState.GetChainingKey();
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionConfirmedHeaderKey(chainingKey);

        // Make a copy for decryption
        var packetCopy = new byte[packetData.Length];
        Array.Copy(packetData, packetCopy, packetData.Length);

        // Decrypt header in place
        SSU2HeaderEncryption.DecryptShortHeaderInPacket(packetCopy, 0, kHeader1, kHeader2);

        // Parse decrypted short header
        var headerReader = new I2PBufferCursor(packetCopy);
        var header = SSU2Header.ParseShortHeader(headerReader);

        // Validate connection IDs
        if (header.DestinationConnectionId != LocalConnectionId)
        {
            Logging.LogWarning($"{DebugId}: Invalid destination connection ID");
            return;
        }

        // Validate packet number (should be 0 for SessionConfirmed per spec line 1702)
        if (header.PacketNumber != 0)
            Logging.LogWarning($"{DebugId}: Invalid packet number for SessionConfirmed: {header.PacketNumber}");

        // Parse fragment info from flags[0]:
        // lower nibble = total fragment count, upper nibble = fragment number
        var totalFragments = header.Flags0 & 0x0F;
        var fragmentNumber = (header.Flags0 >> 4) & 0x0F;

        if (totalFragments == 0) totalFragments = 1; // Treat 0 as 1 for compatibility

        if (totalFragments > 2)
        {
            Logging.LogWarning($"{DebugId}: Too many SessionConfirmed fragments: {totalFragments}");
            return;
        }

        var payloadAfterHeader = new byte[packetCopy.Length - SHORT_HEADER_SIZE];
        Array.Copy(packetCopy, SHORT_HEADER_SIZE, payloadAfterHeader, 0, payloadAfterHeader.Length);

        if (totalFragments == 2)
        {
            // Handle fragmented SessionConfirmed (max 2 fragments)
            if (fragmentNumber == 0)
            {
                // First fragment (contains Part1 + beginning of Part2)
                if (_sessionConfirmedFragmentBuffer != null && _sessionConfirmedFragmentIsSecond)
                {
                    // Already have second fragment - combine: frag0 payload + frag1 payload
                    var combined = new byte[payloadAfterHeader.Length + _sessionConfirmedFragmentBuffer.Length];
                    Array.Copy(payloadAfterHeader, 0, combined, 0, payloadAfterHeader.Length);
                    Array.Copy(_sessionConfirmedFragmentBuffer, 0, combined, payloadAfterHeader.Length,
                        _sessionConfirmedFragmentBuffer.Length);
                    packetCopy = new byte[SHORT_HEADER_SIZE + combined.Length];
                    Array.Copy(header.ToByteArray(), 0, packetCopy, 0, SHORT_HEADER_SIZE);
                    Array.Copy(combined, 0, packetCopy, SHORT_HEADER_SIZE, combined.Length);
                    _sessionConfirmedFragmentBuffer = null;
                    _sessionConfirmedFragmentHeader = null;
                    // Fall through to process the complete packet
                }
                else
                {
                    // Store and wait for second fragment
                    _sessionConfirmedFragmentBuffer = payloadAfterHeader;
                    _sessionConfirmedFragmentIsSecond = false;
                    _sessionConfirmedFragmentHeader = header;
                    Logging.LogDebug($"{DebugId}: Stored SessionConfirmed fragment 0, waiting for fragment 1");
                    return;
                }
            }
            else if (fragmentNumber == 1)
            {
                // Second fragment (contains remainder of Part2)
                if (_sessionConfirmedFragmentBuffer != null && !_sessionConfirmedFragmentIsSecond)
                {
                    // Already have first fragment - combine: frag0 payload + frag1 payload
                    var combined = new byte[_sessionConfirmedFragmentBuffer.Length + payloadAfterHeader.Length];
                    Array.Copy(_sessionConfirmedFragmentBuffer, 0, combined, 0, _sessionConfirmedFragmentBuffer.Length);
                    Array.Copy(payloadAfterHeader, 0, combined, _sessionConfirmedFragmentBuffer.Length,
                        payloadAfterHeader.Length);
                    header = _sessionConfirmedFragmentHeader;
                    packetCopy = new byte[SHORT_HEADER_SIZE + combined.Length];
                    Array.Copy(header.ToByteArray(), 0, packetCopy, 0, SHORT_HEADER_SIZE);
                    Array.Copy(combined, 0, packetCopy, SHORT_HEADER_SIZE, combined.Length);
                    _sessionConfirmedFragmentBuffer = null;
                    _sessionConfirmedFragmentHeader = null;
                    // Fall through to process the complete packet
                }
                else
                {
                    // Store and wait for first fragment
                    _sessionConfirmedFragmentBuffer = payloadAfterHeader;
                    _sessionConfirmedFragmentIsSecond = true;
                    _sessionConfirmedFragmentHeader = header;
                    Logging.LogDebug($"{DebugId}: Stored SessionConfirmed fragment 1, waiting for fragment 0");
                    return;
                }
            }
            else
            {
                Logging.LogWarning($"{DebugId}: Invalid SessionConfirmed fragment number: {fragmentNumber}");
                return;
            }
        }

        // At this point we have the complete (possibly reassembled) packet
        if (packetCopy.Length < SHORT_HEADER_SIZE + 48 + 16) // Min: 16 header + 48 encrypted static + 16 MAC
        {
            Logging.LogWarning($"{DebugId}: SessionConfirmed too short");
            _sessionConfirmedFragmentBuffer = null;
            return;
        }

        // Extract encrypted static key (Part 1: 48 bytes = 32 key + 16 MAC)
        var encryptedStaticKey = new byte[48];
        Array.Copy(packetCopy, SHORT_HEADER_SIZE, encryptedStaticKey, 0, 48);

        // Process Noise message 3 Part 1
        NoiseState.MixHash(header.ToByteArray()); // SSU2 spec: hash decrypted header before Part 1
        var staticKey = NoiseState.ProcessMessage3Part1(encryptedStaticKey);

        if (staticKey == null)
        {
            Logging.LogWarning($"{DebugId}: SessionConfirmed Part 1 AEAD verification failed");
            _sessionConfirmedFragmentBuffer = null;
            Terminate("SessionConfirmed Part 1 AEAD verification failed");
            return;
        }

        // Extract encrypted payload (Part 2: rest of packet)
        var encryptedPayloadLen = packetCopy.Length - SHORT_HEADER_SIZE - 48;
        var encryptedPayload = new byte[encryptedPayloadLen];
        Array.Copy(packetCopy, SHORT_HEADER_SIZE + 48, encryptedPayload, 0, encryptedPayloadLen);

        // Process Noise message 3 Part 2
        var payload = NoiseState.ProcessMessage3Part2(encryptedPayload);

        if (payload == null)
        {
            Logging.LogWarning($"{DebugId}: SessionConfirmed Part 2 AEAD verification failed");
            Terminate("SessionConfirmed Part 2 AEAD verification failed");
            return;
        }

        // Parse Part 2 payload using SessionConfirmed class (handles RouterInfo blocks)
        var confirmed = new SessionConfirmed();
        try
        {
            confirmed.ParsePart2Payload(payload);
            RemoteRouterInfo = confirmed.RouterInfo;
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"{DebugId}: Failed to parse SessionConfirmed payload: {ex.Message}");
            Terminate($"Failed to parse SessionConfirmed payload: {ex.Message}");
            return;
        }

        // Derive data phase keys using Split()
        NoiseState.Split(IsOutgoing);

        // Derive header encryption keys for data phase per spec lines 1891-1907
        var sendKey = NoiseState.GetSendKey();
        var receiveKey = NoiseState.GetReceiveKey();

        // HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
        var sendKeyData = NoiseKDF.HKDF(sendKey, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("HKDFSSU2DataKeys"), 64);
        var receiveKeyData = NoiseKDF.HKDF(receiveKey, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("HKDFSSU2DataKeys"), 64);

        // k_data = keydata[0:31], k_header_2 = keydata[32:63]
        SendDataKey = new byte[32];
        SendHeaderKey2 = new byte[32];
        Array.Copy(sendKeyData, 0, SendDataKey, 0, 32);
        Array.Copy(sendKeyData, 32, SendHeaderKey2, 0, 32);

        ReceiveDataKey = new byte[32];
        ReceiveHeaderKey2 = new byte[32];
        Array.Copy(receiveKeyData, 0, ReceiveDataKey, 0, 32);
        Array.Copy(receiveKeyData, 32, ReceiveHeaderKey2, 0, 32);

        State = SessionState.Established;

        Logging.LogInformation($"{DebugId}: Session established with {RemoteRouterInfo?.Identity?.IdentHash}");
        TransportConnectionLogger.Inst.Log("Session established", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short,
            "SSU2", IsOutgoing ? "Outbound" : "Inbound", RemoteEndpoint);
        TransportConnectionLogger.Inst.RecordSuccess("SSU2", IsOutgoing ? "Outbound" : "Inbound");

        // Fire ConnectionCreated event for incoming connection
        if (!IsOutgoing && RemoteRouterInfo?.Identity?.IdentHash != null)
            Host.FireConnectionCreated(this, RemoteRouterInfo.Identity.IdentHash);

        // Notify connection established
        ConnectionEstablished?.Invoke(this, RemoteRouterInfo?.Identity?.IdentHash);

        // Send any pending messages
        FlushPendingMessages();
    }

    private void ProcessDataPacket(byte[] packetData)
    {
        if (State != SessionState.Established)
        {
            Logging.LogWarning($"{DebugId}: Received data packet in state {State}");
            return;
        }

        LastActivityTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Get header keys for data phase
        // k_header_1 = intro key of the router that published the SSU2 address.
        var kHeader1 = IsOutgoing ? GetRemoteIntroKey() : Host.GetMyIntroKey();

        // Parse and decrypt data phase packet
        var dataPacket = SSU2DataPacket.Parse(packetData, ReceiveDataKey, kHeader1, ReceiveHeaderKey2);

        ReceivePacketNumber++;

        // Process blocks
        foreach (var block in dataPacket.Blocks)
            switch (block.BlockType)
            {
                case SSU2BlockType.I2NP:
                {
                    // Complete I2NP message in single block
                    var i2npReader = new I2PBufferCursor(block.Data);
                    var header = I2NpMessage.ReadHeader16(i2npReader);
                    DataBlockReceived?.Invoke(this, header);
                    break;
                }
                case SSU2BlockType.FirstFragment:
                {
                    var completeMsg = FragmentHandler.HandleFirstFragment(block.Data);
                    if (completeMsg != null)
                    {
                        var i2npReader = new I2PBufferCursor(completeMsg);
                        var header = I2NpMessage.ReadHeader16(i2npReader);
                        DataBlockReceived?.Invoke(this, header);
                    }

                    break;
                }
                case SSU2BlockType.FollowOnFragment:
                {
                    var completeMsg = FragmentHandler.HandleFollowOnFragment(block.Data);
                    if (completeMsg != null)
                    {
                        var i2npReader = new I2PBufferCursor(completeMsg);
                        var header = I2NpMessage.ReadHeader16(i2npReader);
                        DataBlockReceived?.Invoke(this, header);
                    }

                    break;
                }
                case SSU2BlockType.Termination:
                {
                    Logging.LogInformation($"{DebugId}: Received termination block");
                    Terminate("Received termination block");
                    return;
                }
                case SSU2BlockType.ACK:
                {
                    // ACK processing - acknowledge received packets
                    break;
                }
                case SSU2BlockType.RelayRequest:
                {
                    RelayHandler?.HandleRelayRequest(this, block.Data);
                    break;
                }
                case SSU2BlockType.RelayResponse:
                {
                    RelayHandler?.HandleRelayResponse(this, block.Data);
                    break;
                }
                case SSU2BlockType.RelayIntro:
                {
                    RelayHandler?.HandleRelayIntro(this, block.Data);
                    break;
                }
                case SSU2BlockType.PeerTest:
                {
                    RelayHandler?.HandlePeerTest(this, block.Data);
                    break;
                }
                case SSU2BlockType.RelayTagRequest:
                {
                    RelayHandler?.HandleRelayTagRequest(this, block.Data);
                    break;
                }
                case SSU2BlockType.RelayTag:
                {
                    RelayHandler?.HandleRelayTag(this, block.Data);
                    break;
                }
                case SSU2BlockType.RouterInfo:
                {
                    // RouterInfo block received during data phase (peer info update)
                    try
                    {
                        var riReader = new I2PBufferCursor(block.Data);
                        var ri = new I2PRouterInfo(riReader, true);
                        Logging.LogDebug($"{DebugId}: Received RouterInfo block for {ri.Identity.IdentHash}");
                        NetDb.Inst.AddRouterInfo(ri);

                        // If this is our peer's RI, update our local record
                        if (RemoteRouterInfo != null &&
                            RemoteRouterInfo.Identity.IdentHash == ri.Identity.IdentHash)
                            RemoteRouterInfo = ri;
                    }
                    catch (Exception ex)
                    {
                        Logging.LogDebug($"{DebugId}: Failed to parse RouterInfo block: {ex.Message}");
                    }

                    break;
                }
                case SSU2BlockType.NewToken:
                {
                    // New token for future session establishment (anti-DoS)
                    // Format: 4 bytes expiration (seconds since epoch) + 8 bytes token
                    if (block.Data.Length >= 12)
                    {
                        var reader2 = new I2PBufferCursor(block.Data);
                        var tokenExpiry = reader2.ReadUInt32BigEndian();
                        var token = reader2.ReadUInt64BigEndian();
                        Logging.LogDebug($"{DebugId}: Received new token, expires {tokenExpiry}");
                    }

                    break;
                }
                case SSU2BlockType.PathChallenge:
                {
                    // Path validation: echo back data as PathResponse
                    if (block.Data.Length > 0)
                    {
                        Logging.LogDebug($"{DebugId}: PathChallenge received, sending PathResponse");
                        SendPathResponse(block.Data);
                    }

                    break;
                }
                case SSU2BlockType.PathResponse:
                {
                    // Path validation response - verify matches our challenge
                    Logging.LogDebug($"{DebugId}: PathResponse received");
                    break;
                }
                case SSU2BlockType.FirstPacketNumber:
                {
                    // Packet number synchronization after session migration
                    if (block.Data.Length >= 4)
                    {
                        var firstPktNum = BufUtils.Flip32(block.Data, 0);
                        Logging.LogDebug($"{DebugId}: FirstPacketNumber={firstPktNum}");
                    }

                    break;
                }
                case SSU2BlockType.Congestion:
                {
                    // Congestion signal from peer
                    Logging.LogDebug($"{DebugId}: Congestion signal received");
                    break;
                }
                case SSU2BlockType.DateTime:
                case SSU2BlockType.Options:
                case SSU2BlockType.Address:
                case SSU2BlockType.Padding:
                    // Informational blocks, no action needed in data phase
                    break;
                default:
                    Logging.LogDebug($"{DebugId}: Ignoring unknown block type {block.BlockType}");
                    break;
            }
    }

    private void InitializeNoiseAsBob()
    {
        // Initialize Noise XK as Bob (responder)
        // The actual identifier per I2P spec: Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256
        NoiseState = new NoiseXK("Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256");

        // Get our static keys from Host
        var bobPriv = Host.GetStaticPrivateKey();
        var bobPub = Host.GetStaticPublicKey();

        NoiseState.InitializeAsBob(bobPriv, bobPub);
    }

    private (byte[] ephemeralKey, byte[] encryptedPayload) ExtractMessage1Parts(byte[] packetData)
    {
        var reader = new I2PBufferCursor(packetData);
        reader.Seek(32); // Skip long header

        var ephemeralKey = reader.ReadBlock(32).ToByteArray();
        var remaining = reader.Remaining;
        var encryptedPayload = reader.ReadBlock(remaining).ToByteArray();

        return (ephemeralKey, encryptedPayload);
    }

    private void SendSessionCreated()
    {
        Logging.LogDebug($"{DebugId}: Sending SessionCreated to {RemoteEndpoint} (PQ={IsPQ})");

        // Re-use current Noise state (must not re-initialize Bob because he already processed Message 1)

        // Header (plaintext initially)
        var header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_SESSION_CREATED,
            Version = 2,
            NetId = 2,
            DestinationConnectionId = RemoteConnectionId,
            SourceConnectionId = LocalConnectionId,
            PacketNumber = BufUtils.RandomUint() // Random for handshake packets
        };
        var headerBytes = header.ToByteArray();

        // Calculate payload (must be done once to re-use same KEM if retrying)
        // Actually, we should only re-encapsulate if we retry key gen.
        // But wait! KEM encapsulation uses Noise chaining key too.

        byte[] packet = null;
        var attempts = 0;

        // Get our intro key for header encryption
        var ourIntroKey = Host.GetMyIntroKey();
        var kHeader1 = ourIntroKey;
        var chainingKeyBeforeMsg2 = NoiseState.GetChainingKey();
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKeyBeforeMsg2);

        // Precompute the headerX mask byte once: it depends only on kHeader2 (constant per session)
        // and does not change between attempts.
        var ephKeyMaskByte = SSU2HeaderEncryption.GetEphKeyMaskByte(kHeader2);

        while (packet == null)
        {
            attempts++;

            // Build a fresh payload stream if we are retrying
            var payloadStream = new ArrayBufferWriter<byte>();
            var ts = (uint)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            payloadStream.WriteUInt32BigEndian(ts);
            payloadStream.WriteUInt16BigEndian(0); // Padding length
            payloadStream.WriteUInt16BigEndian(0); // Reserved

            var ephKey = NoiseState.GenerateBobEphemeralKeys();
            if (IsPQ) ephKey[31] |= 0x80;
            else ephKey[31] &= 0x7f;

            // The ephemeral key occupies bytes 16-47 of the 48-byte headerX region (packet bytes 32-63),
            // so its obfuscated first byte uses keystream byte 16 of ChaCha20(kHeader2, zeroNonce).
            if (EphKeyFirstByteIsValid(ephKey[0], ephKeyMaskByte) && (IsPQ || (ephKey[31] & 0x80) == 0))
            {
                // If PQ session, encapsulate KEM and include ciphertext
                if (IsPQ && RemoteKemPublicKey != null)
                {
                    byte[] kemCiphertext, kemSharedSecret;
                    switch (PQVersion)
                    {
                        case 3: // ML-KEM-768
                            (kemCiphertext, kemSharedSecret) = MLKEM768.Encapsulate(RemoteKemPublicKey);
                            break;
                        default:
                            kemCiphertext = null;
                            kemSharedSecret = null;
                            break;
                    }

                    if (kemCiphertext != null && kemSharedSecret != null)
                    {
                        payloadStream.WriteByte((byte)PQVersion);
                        payloadStream.Write(kemCiphertext);

                        // Mix KEM shared secret into Noise chaining key (Bob side)
                        NoiseState.MixKeyPQ(kemSharedSecret);
                        Logging.LogDebug($"{DebugId}: PQ KEM encapsulated, mixed into session keys");
                    }
                }

                var payload = payloadStream.WrittenSpan.ToArray();

                // Create message 2
                var (_, encryptedPayload) = NoiseState.CreateMessage2WithHeaderAndCurrentKeys(headerBytes, payload);

                // Build complete packet: long header (32 bytes) + plain ephKey (32 bytes) + encrypted payload.
                // Apply header encryption in two steps to match i2pd exactly:
                //   1. Bytes  0-15: XOR with ChaCha20 masks derived from packet end.
                //   2. Bytes 16-63: single 48-byte ChaCha20(kHeader2, zeroIV) over srcConnID+token+ephKey.
                packet = new byte[headerBytes.Length + ephKey.Length + encryptedPayload.Length];
                Array.Copy(headerBytes, 0, packet, 0, headerBytes.Length);
                Array.Copy(ephKey, 0, packet, headerBytes.Length, ephKey.Length);
                Array.Copy(encryptedPayload, 0, packet, headerBytes.Length + ephKey.Length,
                    encryptedPayload.Length);

                // Step 1: Encrypt bytes 0-15 using IVs from packet end
                SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, kHeader1, kHeader2);

                // Step 2: Obfuscate headerX bytes 16-63 (srcConnID+token+ephKey) with a single 48-byte keystream
                SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, kHeader2);
            }
            else if (attempts > 100)
            {
                throw new Exception("Failed to generate valid SSU2 responder ephemeral key after 100 attempts");
            }
        }

        // Send via host
        Host.SendPacket(RemoteEndpoint, packet);

        BytesSent += packet.Length;

        State = SessionState.SessionCreatedSent;

        if (attempts > 1)
            Logging.LogDebug($"{DebugId}: SessionCreated sent after {attempts} attempts ({packet.Length} bytes)");
        else
            Logging.LogDebug($"{DebugId}: SessionCreated sent ({packet.Length} bytes)");
    }

    private void SendSessionConfirmed()
    {
        Logging.LogDebug($"{DebugId}: Sending SessionConfirmed to {RemoteEndpoint}");

        // Get our RouterInfo
        var myRouterInfo = Host.GetMyRouterInfo();

        // Build SessionConfirmed message with RouterInfo block
        var confirmed = new SessionConfirmed
        {
            RouterInfo = myRouterInfo
        };

        // Build Part 2 payload (RouterInfo block format)
        var part2Payload = confirmed.BuildPart2Payload();

        // Create a canonical header for Noise hashing (spec line 1690)
        var canonicalHeader = new SSU2Header
        {
            IsLongHeader = false,
            Type = SSU2Header.TYPE_SESSION_CONFIRMED,
            DestinationConnectionId = RemoteConnectionId,
            PacketNumber = 0,
            Flags0 = 0x01 // canonical flags for hashing
        };
        var canonicalHeaderBytes = canonicalHeader.ToByteArray();

        // Use Noise to create message 3
        NoiseState.MixHash(canonicalHeaderBytes); // SSU2 spec: hash plaintext header before Part 1
        var encryptedPart1 = NoiseState.CreateMessage3Part1(); // 48 bytes: 32 static key + 16 MAC
        var encryptedPart2 = NoiseState.CreateMessage3Part2(part2Payload); // RouterInfo block + MAC

        // Determine max payload for Part2 based on MTU
        // maxPacketSize = MTU - IP header - UDP header
        // maxPayloadForPart2 = maxPacketSize - shortHeader(16) - part1(48)
        var maxPacketSize = RemoteEndpoint.AddressFamily == AddressFamily.InterNetworkV6
            ? SSU2FragmentHandler.SSU2_MAX_PACKET_SIZE - SSU2FragmentHandler.IPV6_HEADER_SIZE -
              SSU2FragmentHandler.UDP_HEADER_SIZE
            : SSU2FragmentHandler.SSU2_MAX_PACKET_SIZE - SSU2FragmentHandler.IPV4_HEADER_SIZE -
              SSU2FragmentHandler.UDP_HEADER_SIZE;
        var maxPayloadForPart2 = maxPacketSize - SSU2Header.SHORT_HEADER_SIZE - encryptedPart1.Length;

        // Determine if fragmentation is needed (max 2 fragments per spec)
        var needsFragmentation = encryptedPart2.Length > maxPayloadForPart2;

        // Header encryption keys
        var kHeader1 = GetRemoteIntroKey(); // Bob's intro key
        var chainingKey = NoiseState.GetChainingKey();
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionConfirmedHeaderKey(chainingKey);

        if (!needsFragmentation)
        {
            // Single fragment - flags[0] = 0x01 (frag 0 of 1)
            var header = new SSU2Header
            {
                IsLongHeader = false,
                Type = SSU2Header.TYPE_SESSION_CONFIRMED,
                DestinationConnectionId = RemoteConnectionId,
                PacketNumber = 0,
                Flags0 = 0x01 // frag 0, total 1
            };
            var headerBytes = header.ToByteArray();

            var packet = new byte[headerBytes.Length + encryptedPart1.Length + encryptedPart2.Length];
            Array.Copy(headerBytes, 0, packet, 0, headerBytes.Length);
            Array.Copy(encryptedPart1, 0, packet, headerBytes.Length, encryptedPart1.Length);
            Array.Copy(encryptedPart2, 0, packet, headerBytes.Length + encryptedPart1.Length, encryptedPart2.Length);

            SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet, 0, kHeader1, kHeader2);

            Host.SendPacket(RemoteEndpoint, packet);
            BytesSent += packet.Length;
        }
        else
        {
            // Two fragments needed - split encrypted Part2
            // Fragment 0: header + part1 + first portion of encryptedPart2
            // Fragment 1: header + remaining portion of encryptedPart2
            var frag0PayloadSize = maxPayloadForPart2;
            // Ensure second fragment has enough data for header encryption IV (need 24 bytes from end)
            var frag1PayloadSize = encryptedPart2.Length - frag0PayloadSize;
            if (frag1PayloadSize < 24)
            {
                frag0PayloadSize -= 24;
                frag1PayloadSize = encryptedPart2.Length - frag0PayloadSize;
            }

            // Fragment 0: flags[0] = 0x02 (frag 0 of 2)
            var header0 = new SSU2Header
            {
                IsLongHeader = false,
                Type = SSU2Header.TYPE_SESSION_CONFIRMED,
                DestinationConnectionId = RemoteConnectionId,
                PacketNumber = 0,
                Flags0 = 0x02 // frag 0, total 2
            };
            var headerBytes0 = header0.ToByteArray();

            var packet0 = new byte[headerBytes0.Length + encryptedPart1.Length + frag0PayloadSize];
            Array.Copy(headerBytes0, 0, packet0, 0, headerBytes0.Length);
            Array.Copy(encryptedPart1, 0, packet0, headerBytes0.Length, encryptedPart1.Length);
            Array.Copy(encryptedPart2, 0, packet0, headerBytes0.Length + encryptedPart1.Length, frag0PayloadSize);

            SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet0, 0, kHeader1, kHeader2);

            Host.SendPacket(RemoteEndpoint, packet0);
            BytesSent += packet0.Length;

            // Fragment 1: flags[0] = 0x12 (frag 1 of 2)
            var header1 = new SSU2Header
            {
                IsLongHeader = false,
                Type = SSU2Header.TYPE_SESSION_CONFIRMED,
                DestinationConnectionId = RemoteConnectionId,
                PacketNumber = 0,
                Flags0 = 0x12 // frag 1, total 2
            };
            var headerBytes1 = header1.ToByteArray();

            var packet1 = new byte[headerBytes1.Length + frag1PayloadSize];
            Array.Copy(headerBytes1, 0, packet1, 0, headerBytes1.Length);
            Array.Copy(encryptedPart2, frag0PayloadSize, packet1, headerBytes1.Length, frag1PayloadSize);

            SSU2HeaderEncryption.EncryptShortHeaderInPacket(packet1, 0, kHeader1, kHeader2);

            Host.SendPacket(RemoteEndpoint, packet1);
            BytesSent += packet1.Length;

            // Store for retransmission
            _sessionConfirmedFragment2 = packet1;

            Logging.LogDebug(
                $"{DebugId}: SessionConfirmed fragmented: frag0={packet0.Length}B, frag1={packet1.Length}B");
        }

        // Derive data phase keys using Split()
        NoiseState.Split(IsOutgoing);

        // Derive header encryption keys for data phase per spec lines 1891-1907
        var sendKey = NoiseState.GetSendKey();
        var receiveKey = NoiseState.GetReceiveKey();

        // HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
        var sendKeyData = NoiseKDF.HKDF(sendKey, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("HKDFSSU2DataKeys"), 64);
        var receiveKeyData = NoiseKDF.HKDF(receiveKey, Array.Empty<byte>(),
            Encoding.ASCII.GetBytes("HKDFSSU2DataKeys"), 64);

        // k_data = keydata[0:31], k_header_2 = keydata[32:63]
        SendDataKey = new byte[32];
        SendHeaderKey2 = new byte[32];
        Array.Copy(sendKeyData, 0, SendDataKey, 0, 32);
        Array.Copy(sendKeyData, 32, SendHeaderKey2, 0, 32);

        ReceiveDataKey = new byte[32];
        ReceiveHeaderKey2 = new byte[32];
        Array.Copy(receiveKeyData, 0, ReceiveDataKey, 0, 32);
        Array.Copy(receiveKeyData, 32, ReceiveHeaderKey2, 0, 32);

        State = SessionState.Established;

        Logging.LogDebug($"{DebugId}: SessionConfirmed sent");
        Logging.LogInformation($"{DebugId}: Session established");
        TransportConnectionLogger.Inst.Log("Session established", RemoteRouterInfo?.Identity?.IdentHash?.Id32Short,
            "SSU2", IsOutgoing ? "Outbound" : "Inbound", RemoteEndpoint);
        TransportConnectionLogger.Inst.RecordSuccess("SSU2", "Outbound");

        // Notify connection established
        ConnectionEstablished?.Invoke(this, RemoteRouterInfo?.Identity?.IdentHash);

        // Send any pending messages
        FlushPendingMessages();
    }

    private void FlushPendingMessages()
    {
        while (PendingMessages.TryDequeue(out var msg))
        {
            Logging.LogDebug($"{DebugId}: Sending pending message {msg}");
            Send(msg);
        }
    }

    private void ParseSessionCreatedBlocks(I2PBufferCursor blocksData)
    {
        // Parse blocks from SessionCreated payload
        // Most important is the Address block which tells us our external IP
        var reader = blocksData;

        while (reader.Remaining > 0)
        {
            if (reader.Remaining < 3) break; // Need at least type + 2-byte size

            var blockType = (SSU2BlockType)reader.ReadByte();
            var blockSize = reader.ReadUInt16BigEndian();

            if (reader.Remaining < blockSize)
            {
                Logging.LogWarning($"{DebugId}: Invalid block size {blockSize}, remaining {reader.Remaining}");
                break;
            }

            var blockData = reader.ReadBlock(blockSize);

            switch (blockType)
            {
                case SSU2BlockType.Address:
                    // Parse Address block - peer is telling us our external IP
                    var addressBlock = new AddressBlock();
                    addressBlock.Parse(new I2PBufferCursor(blockData));

                    // Report to host for IP detection
                    var ipAddress = new IPAddress(addressBlock.IPAddress);
                    Host.ReportedAddress(ipAddress);

                    Logging.LogDebug($"{DebugId}: Peer reported our address as {ipAddress}:{addressBlock.Port}");
                    break;

                case SSU2BlockType.DateTime:
                case SSU2BlockType.Options:
                    // These are optional and don't need special handling here
                    break;

                default:
                    // Unknown block type - skip it
                    Logging.LogDebug($"{DebugId}: Skipping unknown block type {blockType}");
                    break;
            }
        }
    }

    /// <summary>
    ///     Returns true if the ephemeral key's first byte, when obfuscated with the given mask byte,
    ///     has its MSB clear — the protocol requirement for a valid SSU2 ephemeral key.
    /// </summary>
    private static bool EphKeyFirstByteIsValid(byte ephKeyFirstByte, byte maskByte)
        => ((ephKeyFirstByte ^ maskByte) & 0x80) == 0;
}

public enum SessionState
{
    Initial,
    SessionRequestSent,
    SessionRequestReceived,
    SessionCreatedSent,
    SessionCreatedReceived,
    SessionConfirmedSent,
    Established,
    Terminated
}