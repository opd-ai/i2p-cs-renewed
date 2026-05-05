using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer.SSU2.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Utilities.Encoders;

namespace I2PCore.TransportLayer.SSU2;

/// <summary>
///     Handles SSU2 Relay, PeerTest, and HolePunch protocols.
///     Relay flow: Alice -> Bob (RelayRequest) -> Charlie (RelayIntro)
///     Charlie -> Bob (RelayResponse) -> Alice
///     PeerTest flow: 4 messages (msg 1-4) between Alice, Charlie, and Bob.
///     HolePunch: sent by Charlie to Alice after receiving RelayIntro,
///     encrypted with Alice's intro key.
/// </summary>
public class SSU2RelayHandler
{
    // Status codes for RelayResponse (block type 8)
    public const byte RelayAccept = 0;
    public const byte RelayBobRelayTagNotFound = 5;
    public const byte RelayBobAddressUnreachable = 6;
    public const byte RelayCharlieUnsupported = 65;
    public const byte RelayCharlieSignatureFailure = 66;
    public const byte RelayCharlieAddressesRefused = 69;

    // Status codes for PeerTest (block type 10)
    public const byte PeerTestAccept = 0;
    public const byte PeerTestBobReasonUnspecified = 1;
    public const byte PeerTestBobNoCharlieAvailable = 2;
    public const byte PeerTestBobLimitExceeded = 3;
    public const byte PeerTestBobSignatureFailure = 4;
    public const byte PeerTestCharlieReasonUnspecified = 64;
    public const byte PeerTestCharlieAddressesRefused = 65;
    public const byte PeerTestCharlieNetworkError = 66;
    public const byte PeerTestCharlieSignatureFailure = 67;

    // Expiration durations
    private const int RelaySessionExpirationSeconds = 10;
    private const int PeerTestExpirationSeconds = 60;
    private const int HolePunchMaxRetries = 3;
    private const int HolePunchRetryIntervalMs = 1000;

    public static readonly byte[] RELAY_REQUEST_PROLOGUE = Encoding.ASCII.GetBytes("RelayRequestData");
    public static readonly byte[] RELAY_RESPONSE_PROLOGUE = Encoding.ASCII.GetBytes("RelayAgreementOK");
    public static readonly byte[] PEER_TEST_PROLOGUE = Encoding.ASCII.GetBytes("PeerTestValidate");

    // Manages active relay tags
    private readonly ConcurrentDictionary<uint, RelayTag> ActiveRelayTags = new();

    private readonly SSU2Host Host;

    // Tracks pending peer test sessions by nonce
    private readonly ConcurrentDictionary<uint, PeerTestSession> PendingPeerTests = new();

    // Tracks pending relay sessions by nonce
    private readonly ConcurrentDictionary<uint, RelaySession> PendingRelaySessions = new();

    public SSU2RelayHandler(SSU2Host host)
    {
        Host = host;
    }

    private static byte[] Sign(byte[] prologue, I2PIdentHash h, I2PIdentHash h2, byte[] data, I2PSigningPrivateKey key)
    {
        var bufs = new List<I2PByteBlock> { new(prologue), h.Hash };
        if (h2 != null) bufs.Add(h2.Hash);
        bufs.Add(new I2PByteBlock(data));
        return I2PSignature.DoSign(key, bufs.ToArray());
    }

    private static bool Verify(byte[] prologue, I2PIdentHash h, I2PIdentHash h2, byte[] data, byte[] signature,
        I2PSigningPublicKey key)
    {
        var bufs = new List<I2PByteBlock> { new(prologue), h.Hash };
        if (h2 != null) bufs.Add(h2.Hash);
        bufs.Add(new I2PByteBlock(data));

        var sig = new I2PSignature(new I2PBufferCursor(signature), key.Certificate);
        return I2PSignature.DoVerify(key, sig, bufs.ToArray());
    }

    // ----------------------------------------------------------------
    // Relay Request (block type 7)
    // Format: flags(1) + nonce(4) + relayTag(4) + timestamp(4)
    //         + version(1) + addrSize(1) + addr(var) + signature(var)
    // ----------------------------------------------------------------

    /// <summary>
    ///     Build a RelayRequest block payload (without the 3-byte block header).
    /// </summary>
    public static byte[] BuildRelayRequestData(
        byte flags,
        uint nonce,
        uint relayTag,
        uint timestamp,
        byte version,
        byte[] address,
        byte[] signature)
    {
        var addrLen = address?.Length ?? 0;
        var sigLen = signature?.Length ?? 0;
        var data = new byte[1 + 4 + 4 + 4 + 1 + 1 + addrLen + sigLen];
        var writer = new I2PBufferCursor(data);

        writer.WriteByte(flags);
        writer.WriteUInt32BigEndian(nonce);
        writer.WriteUInt32BigEndian(relayTag);
        writer.WriteUInt32BigEndian(timestamp);
        writer.WriteByte(version);
        writer.WriteByte((byte)addrLen);
        if (addrLen > 0)
            writer.WriteBytes(address);
        if (sigLen > 0)
            writer.WriteBytes(signature);

        return data;
    }

    /// <summary>
    ///     Parse a RelayRequest block payload.
    /// </summary>
    public static RelayRequestData ParseRelayRequestData(byte[] data)
    {
        var reader = new I2PBufferCursor(data);
        var result = new RelayRequestData
        {
            Flags = reader.ReadByte(),
            Nonce = reader.ReadUInt32BigEndian(),
            RelayTag = reader.ReadUInt32BigEndian(),
            Timestamp = reader.ReadUInt32BigEndian(),
            Version = reader.ReadByte()
        };

        var addrSize = reader.ReadByte();
        if (addrSize > 0)
            result.Address = reader.ReadBytes(addrSize);

        // Java signs everything before the signature
        result.RawSignedData = new byte[reader.BaseArrayOffset];
        Array.Copy(data, 0, result.RawSignedData, 0, reader.BaseArrayOffset);

        var remaining = data.Length - reader.BaseArrayOffset;
        if (remaining > 0)
            result.Signature = reader.ReadBytes(remaining);

        return result;
    }

    /// <summary>
    ///     Handle an incoming RelayRequest block on Bob (the introducer).
    ///     Bob looks up the relay tag, then forwards a RelayIntro to Charlie.
    /// </summary>
    public void HandleRelayRequest(SSU2Session fromAlice, byte[] blockData)
    {
        var request = ParseRelayRequestData(blockData);

        Logging.LogDebug($"SSU2Relay: RelayRequest nonce={request.Nonce} relayTag={request.RelayTag}");

        // Look up relay tag to find Charlie's session
        if (!ActiveRelayTags.TryGetValue(request.RelayTag, out var tag))
        {
            Logging.LogDebug($"SSU2Relay: RelayTag {request.RelayTag} not found, sending reject");
            SendRelayResponse(fromAlice, request.Nonce, RelayBobRelayTagNotFound,
                Array.Empty<byte>(), Array.Empty<byte>(), 0);
            return;
        }

        // Verify Alice's signature
        // Alice signs (prologue + Bob + Charlie + data)
        var bobHash = RouterContext.Inst.MyRouterIdentity.IdentHash;
        var charlieHash = tag.Session.RemoteRouterIdentity.IdentHash;

        if (fromAlice.RemoteRouterIdentity?.SigningPublicKey != null)
        {
            if (!Verify(RELAY_REQUEST_PROLOGUE, bobHash, charlieHash, request.RawSignedData, request.Signature,
                    fromAlice.RemoteRouterIdentity.SigningPublicKey))
            {
                Logging.LogWarning(
                    $"SSU2Relay: RelayRequest signature verification failed from Alice {fromAlice.DebugId}");
                // Protocol says to silently drop or reject if sig fails
                return;
            }
        }
        else
        {
            Logging.LogWarning(
                $"SSU2Relay: No signing public key for Alice {fromAlice.DebugId}, cannot verify RelayRequest");
        }

        // Record pending relay session so we can route the response back
        var session = new RelaySession
        {
            Nonce = request.Nonce,
            AliceSession = fromAlice,
            CharlieSession = tag.Session,
            CreatedAt = DateTimeOffset.UtcNow
        };
        PendingRelaySessions[request.Nonce] = session;

        // Build RelayIntro block and send to Charlie
        var aliceHash = fromAlice.RemoteRouterIdentity?.IdentHash?.Hash.ToByteArray();
        if (aliceHash == null)
            aliceHash = new byte[32];

        var introData = BuildRelayIntroData(0, aliceHash, blockData);
        SendBlockToSession(tag.Session, SSU2BlockType.RelayIntro, introData);
    }

    // ----------------------------------------------------------------
    // Relay Response (block type 8)
    // Format: flags(1) + code(1) + nonce(4) + timestamp(4) + version(1)
    //         + csz(1) + addr(var) + signature(var) + token(8)
    // ----------------------------------------------------------------

    /// <summary>
    ///     Build a RelayResponse block payload.
    /// </summary>
    public static byte[] BuildRelayResponseData(
        byte flags,
        byte code,
        uint nonce,
        uint timestamp,
        byte version,
        byte[] address,
        byte[] signature,
        ulong token)
    {
        var addrLen = address?.Length ?? 0;
        var sigLen = signature?.Length ?? 0;
        var data = new byte[1 + 1 + 4 + 4 + 1 + 1 + addrLen + sigLen + 8];
        var writer = new I2PBufferCursor(data);

        writer.WriteByte(flags);
        writer.WriteByte(code);
        writer.WriteUInt32BigEndian(nonce);
        writer.WriteUInt32BigEndian(timestamp);
        writer.WriteByte(version);
        writer.WriteByte((byte)addrLen);
        if (addrLen > 0)
            writer.WriteBytes(address);
        if (sigLen > 0)
            writer.WriteBytes(signature);
        writer.WriteUInt64BigEndian(token);

        return data;
    }

    /// <summary>
    ///     Parse a RelayResponse block payload.
    /// </summary>
    public static RelayResponseData ParseRelayResponseData(byte[] data)
    {
        var reader = new I2PBufferCursor(data);
        var result = new RelayResponseData
        {
            Flags = reader.ReadByte(),
            Code = reader.ReadByte(),
            Nonce = reader.ReadUInt32BigEndian(),
            Timestamp = reader.ReadUInt32BigEndian(),
            Version = reader.ReadByte()
        };

        var csz = reader.ReadByte();
        if (csz > 0)
            result.Address = reader.ReadBytes(csz);

        // Java signs everything before the signature
        result.RawSignedData = new byte[reader.BaseArrayOffset];
        Array.Copy(data, 0, result.RawSignedData, 0, reader.BaseArrayOffset);

        // Remaining minus the last 8 bytes (token) is the signature
        var remaining = data.Length - reader.BaseArrayOffset;
        if (remaining > 8)
        {
            var sigLen = remaining - 8;
            result.Signature = reader.ReadBytes(sigLen);
        }

        result.Token = reader.ReadUInt64BigEndian();
        return result;
    }

    /// <summary>
    ///     Handle an incoming RelayResponse block.
    ///     If received on Bob from Charlie, forward to Alice.
    ///     If received on Alice, process the introduction result.
    /// </summary>
    public void HandleRelayResponse(SSU2Session fromSession, byte[] blockData)
    {
        var response = ParseRelayResponseData(blockData);

        Logging.LogDebug($"SSU2Relay: RelayResponse nonce={response.Nonce} code={response.Code}");

        // If we have a pending relay session for this nonce, we are Bob
        // and should forward to Alice
        if (PendingRelaySessions.TryRemove(response.Nonce, out var relaySession))
        {
            // Verify Charlie's signature
            // Charlie signs (prologue + Bob + null + data)
            var bobHash = RouterContext.Inst.MyRouterIdentity.IdentHash;
            if (relaySession.CharlieSession.RemoteRouterIdentity?.SigningPublicKey != null)
                if (!Verify(RELAY_RESPONSE_PROLOGUE, bobHash, null, response.RawSignedData, response.Signature,
                        relaySession.CharlieSession.RemoteRouterIdentity.SigningPublicKey))
                {
                    Logging.LogWarning(
                        $"SSU2Relay: RelayResponse signature verification failed from Charlie {relaySession.CharlieSession.DebugId}");
                    // Protocol says to silently drop or reject if sig fails
                    return;
                }

            // Forward the RelayResponse block to Alice
            SendBlockToSession(relaySession.AliceSession, SSU2BlockType.RelayResponse, blockData);
            return;
        }

        // Otherwise we are Alice receiving the final response
        if (response.Code == RelayAccept)
            Logging.LogDebug($"SSU2Relay: Relay accepted for nonce={response.Nonce}");
        // The token and address can be used to establish a direct connection
        else
            Logging.LogDebug($"SSU2Relay: Relay rejected for nonce={response.Nonce}, code={response.Code}");
    }

    /// <summary>
    ///     Send a RelayResponse block back on a session.
    /// </summary>
    private void SendRelayResponse(
        SSU2Session session,
        uint nonce,
        byte code,
        byte[] address,
        byte[] signature,
        ulong token)
    {
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var data = BuildRelayResponseData(0, code, nonce, timestamp,
            SSU2Constants.VERSION, address, signature, token);
        SendBlockToSession(session, SSU2BlockType.RelayResponse, data);
    }

    // ----------------------------------------------------------------
    // Relay Intro (block type 9)
    // Format: flags(1) + aliceHash(32) + relayRequestData(var)
    // ----------------------------------------------------------------

    /// <summary>
    ///     Build a RelayIntro block payload.
    /// </summary>
    public static byte[] BuildRelayIntroData(byte flags, byte[] aliceHash, byte[] relayRequestData)
    {
        var reqLen = relayRequestData?.Length ?? 0;
        var data = new byte[1 + 32 + reqLen];
        var writer = new I2PBufferCursor(data);

        writer.WriteByte(flags);
        if (aliceHash != null && aliceHash.Length >= 32)
        {
            var hash32 = new byte[32];
            Array.Copy(aliceHash, 0, hash32, 0, 32);
            writer.WriteBytes(hash32);
        }
        else
        {
            writer.WriteBytes(new byte[32]);
        }

        if (reqLen > 0)
            writer.WriteBytes(relayRequestData);

        return data;
    }

    /// <summary>
    ///     Parse a RelayIntro block payload.
    /// </summary>
    public static RelayIntroData ParseRelayIntroData(byte[] data)
    {
        var reader = new I2PBufferCursor(data);
        var result = new RelayIntroData
        {
            Flags = reader.ReadByte(),
            AliceHash = reader.ReadBytes(32)
        };

        var remaining = data.Length - reader.BaseArrayOffset;
        if (remaining > 0)
            result.RelayRequestData = reader.ReadBytes(remaining);

        return result;
    }

    /// <summary>
    ///     Handle an incoming RelayIntro block on Charlie.
    ///     Charlie should send a RelayResponse back to Bob and
    ///     attempt a HolePunch to Alice.
    /// </summary>
    public void HandleRelayIntro(SSU2Session fromBob, byte[] blockData)
    {
        var intro = ParseRelayIntroData(blockData);

        Logging.LogDebug($"SSU2Relay: RelayIntro received, aliceHash={Convert.ToHexString(intro.AliceHash)}");

        // Parse the embedded relay request to get the nonce and Alice's address
        RelayRequestData request = null;
        if (intro.RelayRequestData != null && intro.RelayRequestData.Length > 0)
            request = ParseRelayRequestData(intro.RelayRequestData);

        var nonce = request?.Nonce ?? 0;
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Charlie signs RelayResponse (prologue + Bob + null + data)
        var bobHash = fromBob.RemoteRouterIdentity.IdentHash;
        var mySigningKey = RouterContext.Inst.PrivateSigningKey;

        // Build data part first to sign it
        var address = request?.Address ?? Array.Empty<byte>();
        var responsePayload = BuildRelayResponseData(0, RelayAccept, nonce, timestamp, SSU2Constants.VERSION, address,
            Array.Empty<byte>(), 0);

        // Extract signed part (everything before signature/token)
        var signedPartLen = 1 + 1 + 4 + 4 + 1 + 1 + address.Length;
        var signedPart = new byte[signedPartLen];
        Array.Copy(responsePayload, 0, signedPart, 0, signedPartLen);

        var signature = Sign(RELAY_RESPONSE_PROLOGUE, bobHash, null, signedPart, mySigningKey);

        // Build and send RelayResponse back to Bob
        var responseData = BuildRelayResponseData(
            0, RelayAccept, nonce, timestamp,
            SSU2Constants.VERSION,
            address,
            signature,
            0);
        SendBlockToSession(fromBob, SSU2BlockType.RelayResponse, responseData);

        // Attempt HolePunch to Alice
        if (address.Length > 0)
        {
            var aliceEndpoint = ParseEndpointFromAddress(address);
            if (aliceEndpoint != null) SendHolePunch(aliceEndpoint, nonce, intro.AliceHash);
        }
    }

    // ----------------------------------------------------------------
    // PeerTest (block type 10)
    // Format: msgNum(1) + code(1) + flags(1) + [hash(32)]
    //         + version(1) + nonce(4) + timestamp(4)
    //         + asz(1) + addr(var) + signature(var)
    //
    // hash is present in messages 2, 3, 4 (not message 1)
    // ----------------------------------------------------------------

    /// <summary>
    ///     Build a PeerTest block payload.
    /// </summary>
    public static byte[] BuildPeerTestData(
        byte msgNum,
        byte code,
        byte flags,
        byte[] hash,
        byte version,
        uint nonce,
        uint timestamp,
        byte[] address,
        byte[] signature)
    {
        var hasHash = hash != null && hash.Length == 32;
        var addrLen = address?.Length ?? 0;
        var sigLen = signature?.Length ?? 0;

        // 1(msgNum) + 1(code) + 1(flags) + [32(hash)] + 1(ver) + 4(nonce) + 4(ts) + 1(asz) + addr + sig
        var size = 3 + (hasHash ? 32 : 0) + 1 + 4 + 4 + 1 + addrLen + sigLen;
        var data = new byte[size];
        var writer = new I2PBufferCursor(data);

        writer.WriteByte(msgNum);
        writer.WriteByte(code);
        writer.WriteByte(flags);
        if (hasHash)
            writer.WriteBytes(hash);
        writer.WriteByte(version);
        writer.WriteUInt32BigEndian(nonce);
        writer.WriteUInt32BigEndian(timestamp);
        writer.WriteByte((byte)addrLen);
        if (addrLen > 0)
            writer.WriteBytes(address);
        if (sigLen > 0)
            writer.WriteBytes(signature);

        return data;
    }

    /// <summary>
    ///     Parse a PeerTest block payload.
    /// </summary>
    public static PeerTestData ParsePeerTestData(byte[] data)
    {
        var reader = new I2PBufferCursor(data);
        var result = new PeerTestData
        {
            MsgNum = reader.ReadByte(),
            Code = reader.ReadByte(),
            Flags = reader.ReadByte()
        };

        // Messages 2, 3, 4 contain a 32-byte hash; message 1 does not
        if (result.MsgNum >= 2) result.Hash = reader.ReadBytes(32);

        result.Version = reader.ReadByte();
        result.Nonce = reader.ReadUInt32BigEndian();
        result.Timestamp = reader.ReadUInt32BigEndian();

        var asz = reader.ReadByte();
        if (asz > 0)
            result.Address = reader.ReadBytes(asz);

        // Java signs everything before the signature
        result.RawSignedData = new byte[reader.BaseArrayOffset];
        Array.Copy(data, 0, result.RawSignedData, 0, reader.BaseArrayOffset);

        var remaining = data.Length - reader.BaseArrayOffset;
        if (remaining > 0)
            result.Signature = reader.ReadBytes(remaining);

        return result;
    }

    /// <summary>
    ///     Handle an incoming PeerTest block.
    ///     Routes based on msgNum (1-7).
    /// </summary>
    public void HandlePeerTest(SSU2Session fromSession, byte[] blockData)
    {
        var pt = ParsePeerTestData(blockData);

        Logging.LogDebug($"SSU2Relay: PeerTest msg={pt.MsgNum} code={pt.Code} nonce={pt.Nonce}");

        var myHash = RouterContext.Inst.MyRouterIdentity.IdentHash;

        switch (pt.MsgNum)
        {
            case 1:
                // Bob receives Msg 1 from Alice (relay)
                if (fromSession?.RemoteRouterIdentity?.SigningPublicKey != null)
                    if (!Verify(PEER_TEST_PROLOGUE, myHash, null, pt.RawSignedData, pt.Signature,
                            fromSession.RemoteRouterIdentity.SigningPublicKey))
                    {
                        Logging.LogWarning(
                            $"SSU2Relay: PeerTest msg 1 signature verification failed from Alice {fromSession.DebugId}");
                        return;
                    }

                HandlePeerTestMsg1(fromSession, pt);
                break;
            case 2:
                // Charlie receives Msg 2 from Bob (relay)
                if (fromSession?.RemoteRouterIdentity?.SigningPublicKey != null)
                {
                    var aliceHash = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
                    if (!Verify(PEER_TEST_PROLOGUE, myHash, aliceHash, pt.RawSignedData, pt.Signature,
                            fromSession.RemoteRouterIdentity.SigningPublicKey))
                    {
                        Logging.LogWarning(
                            $"SSU2Relay: PeerTest msg 2 signature verification failed from Bob {fromSession.DebugId}");
                        return;
                    }
                }

                HandlePeerTestMsg2(fromSession, pt);
                break;
            case 3:
                // Bob receives Msg 3 from Charlie (relay)
                if (fromSession?.RemoteRouterIdentity?.SigningPublicKey != null)
                    if (PendingPeerTests.TryGetValue(pt.Nonce, out var ptSession))
                    {
                        var aliceHash = ptSession.AliceSession.RemoteRouterIdentity.IdentHash;
                        if (!Verify(PEER_TEST_PROLOGUE, myHash, aliceHash, pt.RawSignedData, pt.Signature,
                                fromSession.RemoteRouterIdentity.SigningPublicKey))
                        {
                            Logging.LogWarning(
                                $"SSU2Relay: PeerTest msg 3 signature verification failed from Charlie {fromSession.DebugId}");
                            return;
                        }
                    }

                HandlePeerTestMsg3(fromSession, pt);
                break;
            case 4:
                // Alice receives Msg 4 from Bob (relay)
                if (fromSession?.RemoteRouterIdentity?.SigningPublicKey != null)
                {
                    var charlieHash = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
                    if (!Verify(PEER_TEST_PROLOGUE, myHash, charlieHash, pt.RawSignedData, pt.Signature,
                            fromSession.RemoteRouterIdentity.SigningPublicKey))
                    {
                        Logging.LogWarning(
                            $"SSU2Relay: PeerTest msg 4 signature verification failed from Bob {fromSession.DebugId}");
                        return;
                    }
                }

                HandlePeerTestMsg4(fromSession, pt);
                break;
            case 5:
                // Alice receives Msg 5 from Charlie (direct)
                var charlieHash5 = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
                var charlieRI5 = NetDb.Inst[charlieHash5];
                if (charlieRI5?.Identity?.SigningPublicKey != null)
                    if (!Verify(PEER_TEST_PROLOGUE, myHash, null, pt.RawSignedData, pt.Signature,
                            charlieRI5.Identity.SigningPublicKey))
                    {
                        Logging.LogWarning(
                            $"SSU2Relay: PeerTest msg 5 signature verification failed from Charlie {charlieHash5.Id32Short}");
                        return;
                    }

                HandlePeerTestMsg5(pt);
                break;
            case 6:
                // Charlie receives Msg 6 from Alice (direct)
                var aliceHash6 = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
                var aliceRI6 = NetDb.Inst[aliceHash6];
                if (aliceRI6?.Identity?.SigningPublicKey != null)
                    if (!Verify(PEER_TEST_PROLOGUE, myHash, null, pt.RawSignedData, pt.Signature,
                            aliceRI6.Identity.SigningPublicKey))
                    {
                        Logging.LogWarning(
                            $"SSU2Relay: PeerTest msg 6 signature verification failed from Alice {aliceHash6.Id32Short}");
                        return;
                    }

                HandlePeerTestMsg6(pt);
                break;
            case 7:
                // Bob receives Msg 7 from Charlie (relay)
                if (fromSession?.RemoteRouterIdentity?.SigningPublicKey != null)
                    if (PendingPeerTests.TryGetValue(pt.Nonce, out var ptSession))
                    {
                        var aliceHash = ptSession.AliceSession.RemoteRouterIdentity.IdentHash;
                        if (!Verify(PEER_TEST_PROLOGUE, myHash, aliceHash, pt.RawSignedData, pt.Signature,
                                fromSession.RemoteRouterIdentity.SigningPublicKey))
                        {
                            Logging.LogWarning(
                                $"SSU2Relay: PeerTest msg 7 signature verification failed from Charlie {fromSession.DebugId}");
                            return;
                        }
                    }

                HandlePeerTestMsg7(fromSession, pt);
                break;
            default:
                Logging.LogDebug($"SSU2Relay: Unknown PeerTest msgNum={pt.MsgNum}");
                break;
        }
    }

    /// <summary>
    ///     PeerTest message 1: Alice -> Bob.
    ///     Bob selects Charlie and forwards as message 2 to Charlie.
    /// </summary>
    private void HandlePeerTestMsg1(SSU2Session fromAlice, PeerTestData pt)
    {
        // Record the pending peer test so we can route msg 4 back
        var ptSession = new PeerTestSession
        {
            Nonce = pt.Nonce,
            AliceSession = fromAlice,
            CreatedAt = DateTimeOffset.UtcNow
        };
        PendingPeerTests[pt.Nonce] = ptSession;

        // Bob selects Charlie from established sessions
        var charlie = Host.GetEstablishedSessions()
            .Where(s => s != fromAlice && s.AssignedRelayTag != 0)
            .OrderBy(_ => BufUtils.RandomUint())
            .FirstOrDefault();

        if (charlie == null)
        {
            Logging.LogDebug($"SSU2Relay: No Charlie available for PeerTest nonce={pt.Nonce}");
            // Msg 2 (Error) back to Alice
            SendPeerTestResponse(fromAlice, pt.Nonce, PeerTestBobNoCharlieAvailable, pt.Hash, 0, null);
            return;
        }

        ptSession.CharlieSession = charlie;

        // Forward to Charlie as msg 2
        var aliceHash = fromAlice.RemoteRouterIdentity.IdentHash;
        var charlieHash = charlie.RemoteRouterIdentity.IdentHash;
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // signs (prologue + Charlie + Alice + data)
        // msgNum(1) + code(1) + flags(1) + hash(32) + version(1) + nonce(4) + timestamp(4) + asz(1) + addr
        var signedPart = BuildPeerTestData(
            2, PeerTestAccept, 0,
            aliceHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address ?? Array.Empty<byte>(),
            null); // No sig in signed data

        var signature = Sign(PEER_TEST_PROLOGUE, charlieHash, aliceHash, signedPart,
            RouterContext.Inst.PrivateSigningKey);

        var msg2 = BuildPeerTestData(
            2, PeerTestAccept, 0,
            aliceHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address ?? Array.Empty<byte>(),
            signature);

        SendBlockToSession(charlie, SSU2BlockType.PeerTest, msg2);
        Logging.LogDebug(
            $"SSU2Relay: PeerTest msg1 from Alice, forwarded as msg2 to Charlie {charlie.DebugId}, nonce={pt.Nonce}");
    }

    private void SendPeerTestResponse(SSU2Session session, uint nonce, byte code, byte[] hash, byte flags,
        byte[] address)
    {
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var data = BuildPeerTestData(2, code, flags, hash, SSU2Constants.VERSION, nonce, timestamp, address,
            Array.Empty<byte>());
        SendBlockToSession(session, SSU2BlockType.PeerTest, data);
    }

    /// <summary>
    ///     PeerTest message 2: Bob -> Charlie.
    ///     Charlie sends message 3 to Bob and message 5 to Alice.
    /// </summary>
    private void HandlePeerTestMsg2(SSU2Session fromBob, PeerTestData pt)
    {
        Logging.LogDebug($"SSU2Relay: PeerTest msg2 from Bob {fromBob?.DebugId}, nonce={pt.Nonce}");

        if (fromBob == null) return; // Should not happen for msg 2

        // If we are Alice receiving msg 2, it's an error response from Bob
        if (PendingPeerTests.TryGetValue(pt.Nonce, out var aliceSession) && aliceSession.AliceSession == null)
        {
            ProcessPeerTestResult(pt.Nonce, pt.Code, pt.Address);
            return;
        }

        // We are Charlie. 
        // 1. Send Msg 3 to Bob
        var bobHash = fromBob.RemoteRouterIdentity.IdentHash;
        var aliceHash = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // signs (prologue + Bob + Alice + data)
        var signedPart3 = BuildPeerTestData(
            3, PeerTestAccept, 0,
            bobHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            Array.Empty<byte>(),
            null);
        var signature3 = Sign(PEER_TEST_PROLOGUE, bobHash, aliceHash, signedPart3,
            RouterContext.Inst.PrivateSigningKey);

        var msg3 = BuildPeerTestData(
            3, PeerTestAccept, 0,
            bobHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            Array.Empty<byte>(),
            signature3);
        SendBlockToSession(fromBob, SSU2BlockType.PeerTest, msg3);

        // Record this PeerTest as Charlie so we can handle Msg 6
        PendingPeerTests[pt.Nonce] = new PeerTestSession
        {
            Nonce = pt.Nonce,
            CharlieSession = fromBob, // Store Bob session to send Msg 7 later
            CreatedAt = DateTimeOffset.UtcNow
        };

        // 2. Send Msg 5 to Alice (direct)
        var aliceRI = NetDb.Inst[aliceHash];
        if (aliceRI == null)
        {
            Logging.LogDebug($"SSU2Relay: Charlie could not find Alice {aliceHash} for PeerTest msg 5");
            return;
        }

        var aliceEP = ParseEndpointFromAddress(pt.Address);
        if (aliceEP == null) return;

        var aliceIntroKeyStr = aliceRI.Addresses
            .FirstOrDefault(a => a.TransportStyle == "SSU2")?
            .Options.TryGet("i")?.ToString();

        if (string.IsNullOrEmpty(aliceIntroKeyStr)) return;
        var aliceIntroKey = Base64.Decode(aliceIntroKeyStr);

        // signs (prologue + Alice + null + data)
        var signedPart5 = BuildPeerTestData(
            5, PeerTestAccept, 0,
            RouterContext.Inst.MyRouterIdentity.IdentHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            null);
        var signature5 = Sign(PEER_TEST_PROLOGUE, aliceHash, null, signedPart5, RouterContext.Inst.PrivateSigningKey);

        var msg5 = BuildPeerTestData(
            5, PeerTestAccept, 0,
            RouterContext.Inst.MyRouterIdentity.IdentHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address, // Alice's address as seen by Bob
            signature5);

        SendPeerTestDirect(aliceEP, aliceIntroKey, msg5);
        Logging.LogDebug($"SSU2Relay: Charlie sent PeerTest msg3 to Bob and msg5 to Alice {aliceEP}");
    }

    /// <summary>
    ///     PeerTest message 3: Charlie -> Bob.
    ///     Bob forwards message 4 to Alice.
    /// </summary>
    private void HandlePeerTestMsg3(SSU2Session fromCharlie, PeerTestData pt)
    {
        Logging.LogDebug($"SSU2Relay: PeerTest msg3 from Charlie {fromCharlie?.DebugId}, nonce={pt.Nonce}");

        if (!PendingPeerTests.TryGetValue(pt.Nonce, out var ptSession)) return;

        // Bob forwards Msg 4 to Alice
        var charlieHash = fromCharlie.RemoteRouterIdentity.IdentHash;
        var aliceHash = ptSession.AliceSession.RemoteRouterIdentity.IdentHash;
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // signs (prologue + Alice + Charlie + data)
        var signedPart4 = BuildPeerTestData(
            4, pt.Code, 0,
            charlieHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            null);
        var signature4 = Sign(PEER_TEST_PROLOGUE, aliceHash, charlieHash, signedPart4,
            RouterContext.Inst.PrivateSigningKey);

        var msg4 = BuildPeerTestData(
            4, pt.Code, 0,
            charlieHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            signature4);

        SendBlockToSession(ptSession.AliceSession, SSU2BlockType.PeerTest, msg4);
    }

    /// <summary>
    ///     PeerTest message 4: Bob -> Alice.
    ///     Alice receives this via relay.
    /// </summary>
    private void HandlePeerTestMsg4(SSU2Session fromBob, PeerTestData pt)
    {
        Logging.LogDebug($"SSU2Relay: PeerTest msg4 from Bob {fromBob?.DebugId}, nonce={pt.Nonce}");
        // Alice just waits for msg 5 from Charlie.
    }

    /// <summary>
    ///     PeerTest message 5: Charlie -> Alice (direct).
    ///     Alice confirms reachability and sends Msg 6 to Charlie.
    /// </summary>
    private void HandlePeerTestMsg5(PeerTestData pt)
    {
        Logging.LogDebug($"SSU2Relay: PeerTest msg5 from Charlie (direct), nonce={pt.Nonce}");

        if (!PendingPeerTests.TryGetValue(pt.Nonce, out var ptSession)) return;

        // Alice is reachable!
        ProcessPeerTestResult(pt.Nonce, PeerTestAccept, pt.Address);

        // Send Msg 6 back to Charlie (direct)
        var charlieHash = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
        var charlieRI = NetDb.Inst[charlieHash];
        if (charlieRI == null) return;

        var charlieEP = ParseEndpointFromAddress(pt.Address); // Charlie's addr
        if (charlieEP == null) return;

        var charlieIntroKeyStr = charlieRI.Addresses
            .FirstOrDefault(a => a.TransportStyle == "SSU2")?
            .Options.TryGet("i")?.ToString();
        if (string.IsNullOrEmpty(charlieIntroKeyStr)) return;
        var charlieIntroKey = Base64.Decode(charlieIntroKeyStr);

        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // signs (prologue + Charlie + null + data)
        var signedPart6 = BuildPeerTestData(
            6, PeerTestAccept, 0,
            RouterContext.Inst.MyRouterIdentity.IdentHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            null);
        var signature6 = Sign(PEER_TEST_PROLOGUE, charlieHash, null, signedPart6, RouterContext.Inst.PrivateSigningKey);

        var msg6 = BuildPeerTestData(
            6, PeerTestAccept, 0,
            RouterContext.Inst.MyRouterIdentity.IdentHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            signature6);

        SendPeerTestDirect(charlieEP, charlieIntroKey, msg6);
        Logging.LogDebug($"SSU2Relay: Alice sent PeerTest msg6 to Charlie (direct) {charlieEP}");
    }

    private void HandlePeerTestMsg6(PeerTestData pt)
    {
        Logging.LogDebug($"SSU2Relay: PeerTest msg6 from Alice (direct), nonce={pt.Nonce}");

        if (!PendingPeerTests.TryGetValue(pt.Nonce, out var ptSession)) return;

        // Send Msg 7 to Bob (relay)
        var aliceHash = new I2PIdentHash(new I2PBufferCursor(pt.Hash));
        var bobHash = ptSession.CharlieSession.RemoteRouterIdentity.IdentHash;
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // signs (prologue + Bob + Alice + data)
        var signedPart7 = BuildPeerTestData(
            7, PeerTestAccept, 0,
            aliceHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            null);
        var signature7 = Sign(PEER_TEST_PROLOGUE, bobHash, aliceHash, signedPart7,
            RouterContext.Inst.PrivateSigningKey);

        var msg7 = BuildPeerTestData(
            7, PeerTestAccept, 0,
            aliceHash.Hash.ToByteArray(),
            SSU2Constants.VERSION,
            pt.Nonce,
            timestamp,
            pt.Address,
            signature7);

        SendBlockToSession(ptSession.CharlieSession, SSU2BlockType.PeerTest, msg7);
        PendingPeerTests.TryRemove(pt.Nonce, out _);
    }

    /// <summary>
    ///     PeerTest message 7: Charlie -> Bob.
    ///     Completes the peer test for Bob.
    /// </summary>
    private void HandlePeerTestMsg7(SSU2Session fromCharlie, PeerTestData pt)
    {
        Logging.LogDebug($"SSU2Relay: PeerTest msg7 from Charlie {fromCharlie?.DebugId}, nonce={pt.Nonce}");
        PendingPeerTests.TryRemove(pt.Nonce, out _);
    }

    private void SendPeerTestDirect(IPEndPoint destination, byte[] introKey, byte[] ptData)
    {
        // Build Type 7 DIRECT packet
        var header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_PEER_TEST,
            Version = 2,
            NetId = 2,
            SourceConnectionId = ((ulong)BufUtils.RandomUint() << 32) | BufUtils.RandomUint(),
            DestinationConnectionId = 0,
            PacketNumber = BufUtils.RandomUint()
        };
        var headerBytes = header.ToByteArray();

        // Random ephemeral key (no pre-obfuscation; ObfuscateHeaderX below handles it in the correct position)
        var ephKey = BufUtils.RandomBytes(32);

        // AEAD Payload
        var iv = BufUtils.RandomBytes(12);
        var encryptedPayload = ChaCha20Poly1305.Encrypt(introKey, iv, ptData, headerBytes);

        // Full packet: header(32) + ephKey(32) + payloadWithTag(ptDataLen + 16) + IV1(12) + IV2(12)
        // IV2 is at the very end
        var packet = new byte[32 + 32 + encryptedPayload.Length + 24];
        Array.Copy(headerBytes, 0, packet, 0, 32);
        Array.Copy(ephKey, 0, packet, 32, 32);
        Array.Copy(encryptedPayload, 0, packet, 64, encryptedPayload.Length);

        // Random IV1 at len-24
        var iv1 = BufUtils.RandomBytes(12);
        Array.Copy(iv1, 0, packet, packet.Length - 24, 12);
        // IV2 (used for AEAD) at len-12
        Array.Copy(iv, 0, packet, packet.Length - 12, 12);

        // Step 1: Encrypt bytes 0-15 using IVs from packet end
        SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, introKey, introKey);

        // Step 2: Obfuscate headerX bytes 16-63 (srcConnID+token+ephKey) with a single 48-byte keystream
        SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, introKey);

        Host.SendPacket(destination, packet);
    }

    // ----------------------------------------------------------------
    // Relay Tag management (block types 15 and 16)
    // ----------------------------------------------------------------

    /// <summary>
    ///     Handle a RelayTagRequest block (type 15).
    ///     Allocates a new relay tag for the requesting session.
    /// </summary>
    public void HandleRelayTagRequest(SSU2Session fromSession, byte[] blockData)
    {
        // Allocate a new relay tag
        var tagValue = BufUtils.RandomUint();
        while (tagValue == 0 || ActiveRelayTags.ContainsKey(tagValue))
            tagValue = BufUtils.RandomUint();

        var tag = new RelayTag
        {
            Tag = tagValue,
            Session = fromSession,
            CreatedAt = DateTimeOffset.UtcNow
        };
        ActiveRelayTags[tagValue] = tag;

        // Send RelayTag block (type 16) back with the assigned tag
        var data = new byte[4];
        var writer = new I2PBufferCursor(data);
        writer.WriteUInt32BigEndian(tagValue);

        SendBlockToSession(fromSession, SSU2BlockType.RelayTag, data);

        Logging.LogDebug($"SSU2Relay: Assigned RelayTag {tagValue} to session {fromSession.DebugId}");
    }

    /// <summary>
    ///     Handle a RelayTag block (type 16) received from an introducer.
    ///     Stores the relay tag for use in introducer management.
    /// </summary>
    public void HandleRelayTag(SSU2Session fromSession, byte[] blockData)
    {
        if (blockData.Length < 4)
        {
            Logging.LogDebug("SSU2Relay: RelayTag block too short");
            return;
        }

        var reader = new I2PBufferCursor(blockData);
        var tagValue = reader.ReadUInt32BigEndian();

        fromSession.AssignedRelayTag = tagValue;

        Logging.LogDebug($"SSU2Relay: Received RelayTag {tagValue} from {fromSession.DebugId}");
    }

    /// <summary>
    ///     Request a relay tag from a peer session for introducer use.
    ///     Returns the assigned relay tag, or 0 if the session already has one
    ///     or if the request cannot be made.
    /// </summary>
    public uint RequestRelayTag(SSU2Session session)
    {
        if (session == null || session.State != SessionState.Established)
            return 0;

        // If session already has a relay tag, return it
        if (session.AssignedRelayTag != 0)
            return session.AssignedRelayTag;

        // Send a RelayTagRequest block to the peer
        // The peer will respond with a RelayTag block in a data message
        try
        {
            var requestBlock = new byte[0]; // RelayTagRequest has no data
            session.SendBlock(SSU2BlockType.RelayTagRequest, requestBlock);
            Logging.LogDebug($"SSU2Relay: Requested relay tag from {session.DebugId}");

            // The relay tag will arrive asynchronously via HandleRelayTag
            // For now return 0 (will be populated on next update cycle)
            return 0;
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"SSU2Relay: RequestRelayTag failed: {ex.Message}");
            return 0;
        }
    }

    // ----------------------------------------------------------------
    // HolePunch
    // ----------------------------------------------------------------

    /// <summary>
    ///     Build and send a HolePunch packet to Alice.
    ///     The HolePunch is a long-header packet (type 11) encrypted with
    ///     Alice's intro key. Retries up to 3 times at 1-second intervals.
    /// </summary>
    private void SendHolePunch(IPEndPoint aliceEndpoint, uint nonce, byte[] aliceHash)
    {
        Logging.LogDebug($"SSU2Relay: Sending HolePunch to {aliceEndpoint}, nonce={nonce}");

        // Derive connection ID from nonce
        var connId = nonce | ((ulong)nonce << 32);

        // Build HolePunch payload: DateTime block + Address block
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payloadWriter = new I2PBufferCursor(new byte[64]);

        // DateTime block
        payloadWriter.WriteByte((byte)SSU2BlockType.DateTime);
        payloadWriter.WriteUInt16BigEndian(4);
        payloadWriter.WriteUInt32BigEndian(timestamp);

        var payloadLen = payloadWriter.BaseArrayOffset;
        var payload = new byte[payloadLen];
        Array.Copy(payloadWriter.BaseArray, 0, payload, 0, payloadLen);

        // Build long header for HolePunch (type 11)
        var header = new byte[SSU2Constants.LONG_HEADER_SIZE];
        // Destination connection ID (bytes 0-7)
        header[0] = (byte)((connId >> 56) & 0xFF);
        header[1] = (byte)((connId >> 48) & 0xFF);
        header[2] = (byte)((connId >> 40) & 0xFF);
        header[3] = (byte)((connId >> 32) & 0xFF);
        header[4] = (byte)((connId >> 24) & 0xFF);
        header[5] = (byte)((connId >> 16) & 0xFF);
        header[6] = (byte)((connId >> 8) & 0xFF);
        header[7] = (byte)(connId & 0xFF);
        // Packet number (bytes 8-11)
        var pnBytes = BufUtils.Flip32B(0);
        Array.Copy(pnBytes, 0, header, 8, 4);
        // Type (byte 12) = HolePunch
        header[12] = SSU2Constants.MSG_TYPE_HOLE_PUNCH;
        // Version (byte 13)
        header[13] = SSU2Constants.VERSION;
        // NetId (byte 14)
        header[14] = SSU2Constants.NETWORK_ID;
        // Reserved (byte 15)
        header[15] = 0;
        // Source connection ID (bytes 16-23): use zero; we don't have a session yet
        // Token (bytes 24-31): use zero
        // (already zeroed)

        // Encrypt payload with our intro key, using header as AD
        var introKey = Host.GetMyStaticKey();
        var nonceBuf = ChaCha20Poly1305.CreateNonce(0);
        var encryptedPayload = ChaCha20Poly1305.Encrypt(introKey, nonceBuf, payload, header);

        // Build complete packet
        var packet = new byte[header.Length + encryptedPayload.Length];
        Array.Copy(header, 0, packet, 0, header.Length);
        Array.Copy(encryptedPayload, 0, packet, header.Length, encryptedPayload.Length);

        // Encrypt header with intro key
        SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, introKey, introKey);

        // Send with retries
        for (var attempt = 0; attempt < HolePunchMaxRetries; attempt++)
        {
            Host.SendPacket(aliceEndpoint, packet);
            Logging.LogDebug($"SSU2Relay: HolePunch attempt {attempt + 1}/{HolePunchMaxRetries} to {aliceEndpoint}");

            if (attempt < HolePunchMaxRetries - 1) Thread.Sleep(HolePunchRetryIntervalMs);
        }
    }

    // ----------------------------------------------------------------
    // PeerTest Initiation (NAT Auto-Detection)
    // ----------------------------------------------------------------

    /// <summary>
    ///     Event fired when a peer test completes with a result.
    ///     The result indicates our NAT status.
    /// </summary>
    public event Action<bool, IPEndPoint> PeerTestCompleted;

    /// <summary>
    ///     Initiate a relay request to connect to a firewalled Charlie via Bob.
    /// </summary>
    public bool InitiateRelayRequest(SSU2Session bobSession, I2PIdentHash charlieHash, uint relayTag)
    {
        if (bobSession == null || bobSession.IsTerminated) return false;

        var nonce = BufUtils.RandomUint();
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var bobHash = bobSession.RemoteRouterIdentity?.IdentHash;

        if (bobHash == null) return false;

        // Alice signs RelayRequest (prologue + Bob + Charlie + data)
        // flags(1) + nonce(4) + relayTag(4) + timestamp(4) + version(1) + asz(1) + addr(0)
        var signedPart = new byte[1 + 4 + 4 + 4 + 1 + 1];
        var writer = new I2PBufferCursor(signedPart);
        writer.WriteByte(0); // flags
        writer.WriteUInt32BigEndian(nonce);
        writer.WriteUInt32BigEndian(relayTag);
        writer.WriteUInt32BigEndian(timestamp);
        writer.WriteByte(SSU2Constants.VERSION);
        writer.WriteByte(0); // asz

        var signature = Sign(RELAY_REQUEST_PROLOGUE, bobHash, charlieHash, signedPart,
            RouterContext.Inst.PrivateSigningKey);

        var relayData = BuildRelayRequestData(
            0, // flags
            nonce,
            relayTag,
            timestamp,
            SSU2Constants.VERSION,
            Array.Empty<byte>(),
            signature);

        SendBlockToSession(bobSession, SSU2BlockType.RelayRequest, relayData);

        Logging.LogInformation(
            $"SSU2Relay: Initiated RelayRequest for Charlie {charlieHash.Id32Short} via Bob {bobSession.DebugId}");
        return true;
    }

    /// <summary>
    ///     Initiate a peer test to determine our NAT status.
    ///     We are Alice: send msg 1 to Bob (an established peer), who will
    ///     select Charlie to test our reachability.
    /// </summary>
    public bool InitiatePeerTest(SSU2Session bobSession)
    {
        if (bobSession == null || bobSession.IsTerminated) return false;

        var nonce = BufUtils.RandomUint();
        var timestamp = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var myHash = RouterContext.Inst.MyRouterIdentity?.IdentHash;
        var bobHash = bobSession.RemoteRouterIdentity?.IdentHash;

        if (myHash == null || bobHash == null) return false;

        // Alice signs PeerTest msg 1 (prologue + Bob + null + data)
        // msgNum(1) + code(1) + flags(1) + hash(0) + version(1) + nonce(4) + timestamp(4) + asz(1) + addr(0)
        var signedPart = new byte[1 + 1 + 1 + 1 + 4 + 4 + 1];
        var writer = new I2PBufferCursor(signedPart);
        writer.WriteByte(1); // msg 1
        writer.WriteByte(PeerTestAccept);
        writer.WriteByte(0); // flags
        writer.WriteByte(SSU2Constants.VERSION);
        writer.WriteUInt32BigEndian(nonce);
        writer.WriteUInt32BigEndian(timestamp);
        writer.WriteByte(0); // asz

        var signature = Sign(PEER_TEST_PROLOGUE, bobHash, null, signedPart, RouterContext.Inst.PrivateSigningKey);

        var ptData = BuildPeerTestData(
            1, // msg 1
            PeerTestAccept,
            0, // flags
            null, // no hash in msg 1
            SSU2Constants.VERSION,
            nonce,
            timestamp,
            Array.Empty<byte>(),
            signature);

        // Track the peer test
        PendingPeerTests[nonce] = new PeerTestSession
        {
            Nonce = nonce,
            AliceSession = bobSession,
            CreatedAt = DateTimeOffset.UtcNow
        };

        SendBlockToSession(bobSession, SSU2BlockType.PeerTest, ptData);

        Logging.LogInformation($"SSU2Relay: Initiated PeerTest with nonce={nonce} via {bobSession.DebugId}");
        return true;
    }

    /// <summary>
    ///     Process the result of a completed peer test.
    ///     Updates RouterContext.IsFirewalled based on results.
    /// </summary>
    internal void ProcessPeerTestResult(uint nonce, byte code, byte[] address)
    {
        if (!PendingPeerTests.TryGetValue(nonce, out var session)) return;

        session.Completed = true;
        session.ResultCode = code;

        if (address != null && address.Length > 0) session.ReportedAddress = ParseEndpointFromAddress(address);

        var isReachable = code == PeerTestAccept;

        Logging.LogInformation($"SSU2Relay: PeerTest result nonce={nonce}: " +
                               $"reachable={isReachable}, code={code}, " +
                               $"addr={session.ReportedAddress}");

        // Update router's firewall status
        RouterContext.Inst.IsFirewalled = !isReachable;

        PeerTestCompleted?.Invoke(isReachable, session.ReportedAddress);
    }

    // ----------------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------------

    /// <summary>
    ///     Remove expired relay sessions (10s) and peer test sessions (60s).
    ///     Should be called periodically from the host maintenance loop.
    /// </summary>
    public void CleanupExpiredSessions()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var kvp in PendingRelaySessions)
            if ((now - kvp.Value.CreatedAt).TotalSeconds > RelaySessionExpirationSeconds)
                PendingRelaySessions.TryRemove(kvp.Key, out _);

        foreach (var kvp in PendingPeerTests)
            if ((now - kvp.Value.CreatedAt).TotalSeconds > PeerTestExpirationSeconds)
                PendingPeerTests.TryRemove(kvp.Key, out _);
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /// <summary>
    ///     Send a single block as a data packet on an existing session.
    /// </summary>
    private void SendBlockToSession(SSU2Session session, SSU2BlockType blockType, byte[] blockData)
    {
        if (session == null || session.IsTerminated) return;
        session.SendBlock(blockType, blockData);
        Logging.LogDebug($"SSU2Relay: Sent {blockType} block ({blockData.Length} bytes) on {session.DebugId}");
    }

    /// <summary>
    ///     Parse an IP endpoint from a variable-length address field.
    ///     6 bytes = IPv4 (4 addr + 2 port), 18 bytes = IPv6 (16 addr + 2 port).
    /// </summary>
    private static IPEndPoint ParseEndpointFromAddress(byte[] addr)
    {
        if (addr == null)
            return null;

        if (addr.Length == 6)
        {
            // IPv4
            var ip = new IPAddress(new[] { addr[0], addr[1], addr[2], addr[3] });
            var port = (ushort)((addr[4] << 8) | addr[5]);
            return new IPEndPoint(ip, port);
        }

        if (addr.Length == 18)
        {
            // IPv6
            var ipBytes = new byte[16];
            Array.Copy(addr, 0, ipBytes, 0, 16);
            var ip = new IPAddress(ipBytes);
            var port = (ushort)((addr[16] << 8) | addr[17]);
            return new IPEndPoint(ip, port);
        }

        Logging.LogDebug($"SSU2Relay: Unexpected address length {addr.Length}");
        return null;
    }
}

// ====================================================================
// Data structures
// ====================================================================

/// <summary>
///     Tracks a pending relay session while waiting for Charlie's response.
/// </summary>
public class RelaySession
{
    public SSU2Session AliceSession;
    public SSU2Session CharlieSession;
    public DateTimeOffset CreatedAt;
    public uint Nonce;
}

/// <summary>
///     Represents an active relay tag assigned to a session.
/// </summary>
public class RelayTag
{
    public DateTimeOffset CreatedAt;
    public SSU2Session Session;
    public uint Tag;
}

/// <summary>
///     Tracks a pending peer test session.
/// </summary>
public class PeerTestSession
{
    public SSU2Session AliceSession;
    public SSU2Session CharlieSession;
    public bool Completed;
    public DateTimeOffset CreatedAt;
    public uint Nonce;
    public IPEndPoint ReportedAddress;
    public byte ResultCode;
}

/// <summary>
///     Parsed data from a RelayRequest block (type 7).
/// </summary>
public class RelayRequestData
{
    public byte[] Address;
    public byte Flags;
    public uint Nonce;
    public byte[] RawSignedData;
    public uint RelayTag;
    public byte[] Signature;
    public uint Timestamp;
    public byte Version;
}

/// <summary>
///     Parsed data from a RelayResponse block (type 8).
/// </summary>
public class RelayResponseData
{
    public byte[] Address;
    public byte Code;
    public byte Flags;
    public uint Nonce;
    public byte[] RawSignedData;
    public byte[] Signature;
    public uint Timestamp;
    public ulong Token;
    public byte Version;
}

/// <summary>
///     Parsed data from a RelayIntro block (type 9).
/// </summary>
public class RelayIntroData
{
    public byte[] AliceHash;
    public byte Flags;
    public byte[] RelayRequestData;
}

/// <summary>
///     Parsed data from a PeerTest block (type 10).
/// </summary>
public class PeerTestData
{
    public byte[] Address;
    public byte Code;
    public byte Flags;
    public byte[] Hash;
    public byte MsgNum;
    public uint Nonce;
    public byte[] RawSignedData;
    public byte[] Signature;
    public uint Timestamp;
    public byte Version;
}