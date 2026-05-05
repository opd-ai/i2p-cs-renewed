using System;
using System.Linq;
using System.Text;
using I2PCore.Crypto;
using I2PCore.Crypto.Noise;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;

namespace I2PCore.TunnelLayer.ECIES;

/// <summary>
///     ECIES Tunnel Decryption
///     Processes incoming ECIES tunnel build requests
///     Decrypts using Noise N pattern with router's static keypair
/// </summary>
public class ECIESTunnelDecrypt
{
    private readonly byte[] _staticPrivateKey;
    private readonly byte[] _staticPublicKey;

    // Saved from the last successful Noise N handshake
    private byte[] _lastChainingKey;
    private byte[] _lastHandshakeHash;

    public ECIESTunnelDecrypt(byte[] staticPrivateKey, byte[] staticPublicKey)
    {
        if (staticPrivateKey == null)
            throw new ArgumentNullException(nameof(staticPrivateKey));

        if (staticPublicKey == null)
            throw new ArgumentNullException(nameof(staticPublicKey));

        // Extract X25519 part from Hybrid keys if needed
        if (staticPrivateKey.Length != 32)
            staticPrivateKey = staticPrivateKey.Skip(staticPrivateKey.Length - 32).Take(32).ToArray();

        if (staticPublicKey.Length != 32)
            staticPublicKey = staticPublicKey.Skip(staticPublicKey.Length - 32).Take(32).ToArray();

        _staticPrivateKey = staticPrivateKey;
        _staticPublicKey = staticPublicKey;
    }

    /// <summary>
    ///     Process a ShortTunnelBuildMessage.
    ///     Checks the first 16 bytes of each record against our router hash,
    ///     then attempts Noise N decryption on matching records.
    /// </summary>
    public TunnelBuildResult ProcessShortTunnelBuild(ShortTunnelBuildMessage message)
    {
        if (message == null)
            throw new ArgumentNullException(nameof(message));

        var ourHashPrefix = new byte[16];
        Array.Copy(RouterContext.Inst.MyRouterIdentity.IdentHash.Hash.ToByteArray(), 0, ourHashPrefix, 0, 16);

        for (var i = 0; i < message.Records.Count; i++)
        {
            var encryptedRecord = message.Records[i];
            if (encryptedRecord.IsEmpty || encryptedRecord.Length != ShortBuildRequestRecord.OnWireRecordSize)
                continue;

            // Java BuildMessageProcessor.java: fast routing prefix check.
            // Correctly layered encryption (ApplyLayeredEncryption) ensures that
            // the first 16 bytes match the target hop's hash prefix when it receives it.
            var match = true;
            for (var j = 0; j < 16; ++j)
                if (encryptedRecord[j] != ourHashPrefix[j])
                {
                    match = false;
                    break;
                }

            if (!match) continue;

            try
            {
                var decryptedRecord = DecryptShortRecord(encryptedRecord);

                return new TunnelBuildResult
                {
                    Success = true,
                    RecordIndex = i,
                    ShortRequest = decryptedRecord,
                    IsShortFormat = true,
                    ChainingKey = _lastChainingKey,
                    HandshakeHash = _lastHandshakeHash
                };
            }
            catch (Exception ex)
            {
                Logging.LogDebug($"ECIESTunnelDecrypt: Failed to decrypt record {i}: {ex.Message}");
            }
        }

        return new TunnelBuildResult
        {
            Success = false,
            RecordIndex = -1
        };
    }

    /// <summary>
    ///     Decrypt a short build request record using Noise N pattern.
    ///     On-wire format (218 bytes): routerHash[0:16] (16) + NoiseN message (202).
    ///     Strips the 16-byte router hash prefix before passing to Noise N.
    ///     Saves chaining key and handshake hash for reply key derivation.
    /// </summary>
    public ShortBuildRequestRecord DecryptShortRecord(I2PByteBlock encryptedRecord)
    {
        if (encryptedRecord.IsEmpty || encryptedRecord.Length != ShortBuildRequestRecord.OnWireRecordSize)
            throw new ArgumentException(
                $"Encrypted record must be {ShortBuildRequestRecord.OnWireRecordSize} bytes, got {encryptedRecord.Length}",
                nameof(encryptedRecord));

        // Strip the 16-byte router hash prefix; Noise N message starts at offset 16
        var noiseMessage = new byte[encryptedRecord.Length - ShortBuildRequestRecord.EncryptedOffset];
        encryptedRecord.Peek(noiseMessage, ShortBuildRequestRecord.EncryptedOffset, 0, noiseMessage.Length);

        var noiseN = NoiseN.CreateResponder(_staticPrivateKey, _staticPublicKey);
        var plaintext = noiseN.ProcessMessage(noiseMessage);

        // Save handshake state for reply key derivation
        _lastChainingKey = noiseN.GetChainingKey();
        _lastHandshakeHash = noiseN.GetHash();
        noiseN.Dispose();

        if (plaintext.Length != ShortBuildRequestRecord.ClearTextSize)
            throw new InvalidOperationException(
                $"Decrypted record is {plaintext.Length} bytes, expected {ShortBuildRequestRecord.ClearTextSize}");

        return new ShortBuildRequestRecord(new I2PBufferCursor(plaintext));
    }

    /// <summary>
    ///     Decrypt a long build request record using Noise N pattern
    /// </summary>
    public LongBuildRequestRecord DecryptLongRecord(I2PByteBlock encryptedRecord)
    {
        if (encryptedRecord.IsEmpty || encryptedRecord.Length != LongBuildRequestRecord.EncryptedRecordSize)
            throw new ArgumentException(
                $"Encrypted record must be {LongBuildRequestRecord.EncryptedRecordSize} bytes",
                nameof(encryptedRecord));

        // Strip the 16-byte router hash prefix
        var noiseMessage = new byte[encryptedRecord.Length - 16];
        encryptedRecord.Peek(noiseMessage, 16, 0, noiseMessage.Length);

        var noiseN = NoiseN.CreateResponder(_staticPrivateKey, _staticPublicKey);
        var plaintext = noiseN.ProcessMessage(noiseMessage);

        _lastChainingKey = noiseN.GetChainingKey();
        _lastHandshakeHash = noiseN.GetHash();
        noiseN.Dispose();

        if (plaintext.Length != LongBuildRequestRecord.UnencryptedRecordSize)
            throw new InvalidOperationException(
                $"Decrypted record is {plaintext.Length} bytes, expected {LongBuildRequestRecord.UnencryptedRecordSize}");

        return new LongBuildRequestRecord(new I2PBufferCursor(plaintext));
    }

    /// <summary>
    ///     Create an encrypted reply for a short tunnel build request.
    ///     Derives reply key from Noise handshake CK via HKDF chain (matching Java BuildRequestRecord).
    ///     Reply is AEAD-encrypted with ChaChaPoly (key=replyKey, nonce=slotNumber, AD=handshakeHash).
    ///     Also derives layer key and IV key for the transit tunnel.
    /// </summary>
    public (byte[] EncryptedReply, byte[] ReplyKey, byte[] LayerKey, byte[] IvKey, byte[] GarlicKey, ulong GarlicTag)
        CreateShortReply(
            ShortBuildRequestRecord request,
            ShortBuildReplyRecord.TunnelBuildReplyStatus status,
            int slotNumber,
            I2PMapping options = null)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));
        if (_lastChainingKey == null || _lastHandshakeHash == null)
            throw new InvalidOperationException("No handshake state available - call DecryptShortRecord first");

        var reply = new ShortBuildReplyRecord(status, options);

        // Derive keys from Noise CK using HKDF chain (same as Java BuildRequestRecord lines 443-464)
        var (layerKey, ivKey, replyKey, replyAD, garlicKey, garlicTag) = ShortBuildRequestRecord.DeriveAllKeys(
            _lastChainingKey, _lastHandshakeHash, request.IsOutboundEndpoint());

        // AEAD encrypt: ChaChaPoly(replyKey, nonce=slotNumber, AD=handshakeHash, plaintext)
        var plaintext = reply.ToByteArray();
        var nonce = ChaCha20Poly1305.CreateNonce((ulong)slotNumber);

        var encrypted = ChaCha20Poly1305.Encrypt(replyKey, nonce, plaintext, _lastHandshakeHash);

        return (encrypted, replyKey, layerKey, ivKey, garlicKey, garlicTag);
    }

    /// <summary>
    ///     HKDF expand-only step matching Java's sequential CK derivation.
    ///     HKDF(ck[0:32], empty, info) -> ck[0:32] = newCK, ck[32:64] = derivedKey
    /// </summary>
    private static void DeriveNextKey(byte[] ck, string info)
    {
        var salt = new byte[32];
        Array.Copy(ck, 0, salt, 0, 32);
        var derived = NoiseKDF.HKDF(salt,
            null, Encoding.ASCII.GetBytes(info), 64);
        Array.Copy(derived, 0, ck, 0, 64);
    }
}

/// <summary>
///     Result of processing a tunnel build request
/// </summary>
public class TunnelBuildResult
{
    public bool Success { get; set; }
    public int RecordIndex { get; set; }
    public ShortBuildRequestRecord ShortRequest { get; set; }
    public LongBuildRequestRecord LongRequest { get; set; }
    public bool IsShortFormat { get; set; }

    /// <summary>
    ///     Chaining key from the Noise N handshake (for key derivation)
    /// </summary>
    public byte[] ChainingKey { get; set; }

    /// <summary>
    ///     Handshake hash from Noise N (for AEAD reply AD)
    /// </summary>
    public byte[] HandshakeHash { get; set; }
}