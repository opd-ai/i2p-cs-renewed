using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using I2PCore.Crypto;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.Data;

/// <summary>
///     EncryptedLeaseSet structure - DatabaseStore type 5.
///     Only the blinded key and expiration are visible in cleartext.
///     The actual lease set is encrypted for privacy.
///     Supported as of 0.9.38 (proposal 123).
/// </summary>
public class I2PEncryptedLeaseSet : I2PType, ILeaseSet
{
    [Flags]
    public enum EncryptedLeaseSetFlags : ushort
    {
        None = 0x00,
        OfflineKey = 0x01,
        Unpublished = 0x02
    }

    private static readonly I2PByteBlock FiveBl = BufUtils.To8Bl(5);

    // Cached decrypted lease set (if decrypted)
    private ILeaseSet DecryptedLeaseSet;

    /// <summary>
    ///     Create a new EncryptedLeaseSet for publishing
    /// </summary>
    public I2PEncryptedLeaseSet(
        I2PSigningPublicKey blindedPublicKey,
        I2PDateShort published,
        ushort expiresSeconds,
        EncryptedLeaseSetFlags flags,
        I2PByteBlock encryptedData,
        I2PSignature signature,
        I2POfflineSignature offlineSignature = null)
    {
        BlindedSigType = blindedPublicKey.Certificate.SignatureType;
        BlindedPublicKey = blindedPublicKey;
        Published = published;
        ExpiresSeconds = expiresSeconds;
        Flags = flags;
        OfflineSignature = offlineSignature;
        EncryptedData = encryptedData;
        Signature = signature;
    }

    /// <summary>
    ///     Parse EncryptedLeaseSet from buffer
    /// </summary>
    public I2PEncryptedLeaseSet(I2PBufferCursor reader)
    {
        var startPos = reader.Position;

        BlindedSigType = (I2PSigningKey.SigningKeyTypes)reader.ReadUInt16BigEndian();
        var blindedCert = new I2PCertificate(BlindedSigType);
        BlindedPublicKey = new I2PSigningPublicKey(reader, blindedCert);

        Published = new I2PDateShort(reader);
        ExpiresSeconds = reader.ReadUInt16BigEndian();
        Flags = (EncryptedLeaseSetFlags)reader.ReadUInt16BigEndian();

        if (Flags.HasFlag(EncryptedLeaseSetFlags.OfflineKey))
            OfflineSignature = new I2POfflineSignature(reader, blindedCert);

        var encryptedDataLen = reader.ReadUInt16BigEndian();
        EncryptedData = reader.ReadBlock(encryptedDataLen);

        var body = reader.BlockSince(startPos);

        var sigCert = OfflineSignature?.TransientPublicKey.Certificate ?? blindedCert;
        Signature = new I2PSignature(reader, sigCert);

        // Verify signature
        var spkey = OfflineSignature?.TransientPublicKey ?? BlindedPublicKey;
        var versig = I2PSignature.DoVerify(spkey, Signature, FiveBl, body);
        if (!versig)
        {
            var msg = $"I2PEncryptedLeaseSet: I2PSignature.DoVerify failed: {spkey.Certificate.SignatureType}";
            Logging.LogDebug(msg);
            throw new SignatureCheckFailureException(msg);
        }
    }

    public I2PSigningKey.SigningKeyTypes BlindedSigType { get; set; }
    public I2PSigningPublicKey BlindedPublicKey { get; set; }
    public I2PDateShort Published { get; set; }
    public ushort ExpiresSeconds { get; set; }
    public EncryptedLeaseSetFlags Flags { get; set; }
    public I2POfflineSignature OfflineSignature { get; set; }
    public I2PByteBlock EncryptedData { get; set; }
    public I2PSignature Signature { get; set; }

    public void Write(IBufferWriter<byte> dest)
    {
        dest.WriteUInt16BigEndian((ushort)BlindedSigType);
        BlindedPublicKey.Write(dest);
        Published.Write(dest);
        dest.WriteUInt16BigEndian(ExpiresSeconds);
        dest.WriteUInt16BigEndian((ushort)Flags);

        if (Flags.HasFlag(EncryptedLeaseSetFlags.OfflineKey)) OfflineSignature?.Write(dest);

        dest.WriteUInt16BigEndian((ushort)EncryptedData.Length);
        dest.WriteBlock(EncryptedData);
        Signature.Write(dest);
    }

    public DatabaseStoreMessage.MessageContent MessageType => DatabaseStoreMessage.MessageContent.EncryptedLeaseSet;

    // ILeaseSet implementation
    public I2PDestination Destination =>
        // For encrypted leasesets, we don't have access to the actual destination
        // until it's decrypted. Return null or the decrypted destination.
        DecryptedLeaseSet?.Destination;

    public DateTime Expire => (DateTime)Published + TimeSpan.FromSeconds(ExpiresSeconds);

    public IEnumerable<ILease> Leases =>
        DecryptedLeaseSet?.Leases ??
        Enumerable.Empty<ILease>();

    public IEnumerable<I2PPublicKey> PublicKeys =>
        DecryptedLeaseSet?.PublicKeys ??
        Enumerable.Empty<I2PPublicKey>();

    public void RemoveExpired()
    {
        DecryptedLeaseSet?.RemoveExpired();
    }

    byte[] ILeaseSet.ToByteArray()
    {
        var stream = new ArrayBufferWriter<byte>();
        Write(stream);
        return stream.WrittenSpan.ToArray();
    }

    /// <summary>
    ///     Decrypt the encrypted lease set using a BlindedPublicKey.
    ///     Implements proposal 123: two-layer ChaCha20 encryption.
    /// </summary>
    /// <param name="blindingKey">The BlindedPublicKey derived from the destination identity</param>
    /// <param name="leaseSet">Decrypted inner lease set on success</param>
    /// <param name="clientSecret">Optional client authentication secret (32 bytes)</param>
    /// <returns>True if decryption succeeded</returns>
    public bool TryDecrypt(BlindedPublicKey blindingKey, out ILeaseSet leaseSet, byte[] clientSecret = null)
    {
        leaseSet = null;

        if (blindingKey == null || EncryptedData.IsEmpty || EncryptedData.Length < 32)
        {
            Logging.LogDebug("I2PEncryptedLeaseSet: Invalid parameters for decryption");
            return false;
        }

        try
        {
            // Get date string from published timestamp
            var publishedDt = (DateTime)Published;
            var dateStr = publishedDt.ToString("yyyyMMdd");

            // Get blinded key and verify it matches
            var blindedKey = blindingKey.GetBlindedKey(dateStr);
            if (blindedKey == null)
            {
                Logging.LogDebug("I2PEncryptedLeaseSet: Failed to compute blinded key");
                return false;
            }

            var storedBlindedKey = new byte[BlindedPublicKey.Key.Length];
            Array.Copy(BlindedPublicKey.Key.BaseArray, BlindedPublicKey.Key.BaseArrayOffset,
                storedBlindedKey, 0, storedBlindedKey.Length);

            if (!ByteArraysEqual(blindedKey, storedBlindedKey))
            {
                Logging.LogDebug("I2PEncryptedLeaseSet: Blinded public key doesn't match");
                return false;
            }

            // outerInput = subcredential || publishedTimestamp (4 bytes BE)
            var subcredential = blindingKey.GetSubcredential(blindedKey);
            var outerInput = new byte[36];
            Array.Copy(subcredential, 0, outerInput, 0, 32);
            var timestamp = (uint)Published;
            outerInput[32] = (byte)(timestamp >> 24);
            outerInput[33] = (byte)(timestamp >> 16);
            outerInput[34] = (byte)(timestamp >> 8);
            outerInput[35] = (byte)(timestamp & 0xFF);

            var encData = EncryptedData.ToByteArray();

            // Layer 1 decryption
            // outerSalt = encryptedData[0:32]
            var outerSalt = new byte[32];
            Array.Copy(encData, 0, outerSalt, 0, 32);

            // keys = HKDF(outerSalt, outerInput, "ELS2_L1K", 44)
            var info1 = Encoding.ASCII.GetBytes("ELS2_L1K");
            var keys1 = HKDF.DeriveKey(outerSalt, outerInput, info1, 44);
            var outerKey = new byte[32];
            var outerIV = new byte[12];
            Array.Copy(keys1, 0, outerKey, 0, 32);
            Array.Copy(keys1, 32, outerIV, 0, 12);

            // Decrypt Layer 1: ChaCha20(outerCiphertext[32:], outerKey, outerIV)
            var lenOuterPlaintext = encData.Length - 32;
            var outerPlaintext = new byte[lenOuterPlaintext];
            ChaCha20Decrypt(encData, 32, lenOuterPlaintext, outerKey, outerIV, outerPlaintext);

            // Parse Layer 1: flags byte, optional auth data, then inner ciphertext
            var outerOffset = 0;
            var layer1Flags = outerPlaintext[outerOffset++];
            var authDataLen = 0;

            byte[] innerInput;
            if ((layer1Flags & 0x01) != 0) // client auth present
            {
                authDataLen = ExtractClientAuthData(
                    outerPlaintext, outerOffset, lenOuterPlaintext - outerOffset,
                    clientSecret, outerInput, out innerInput);
                if (authDataLen < 0)
                {
                    Logging.LogDebug("I2PEncryptedLeaseSet: Client authentication failed");
                    return false;
                }
            }
            else
            {
                innerInput = outerInput; // No auth: innerInput = subcredential || publishedTimestamp
            }

            // Layer 2 decryption
            var innerCiphertextOffset = outerOffset + authDataLen;
            // innerSalt = innerCiphertext[0:32]
            var innerSalt = new byte[32];
            Array.Copy(outerPlaintext, innerCiphertextOffset, innerSalt, 0, 32);

            var info2 = Encoding.ASCII.GetBytes("ELS2_L2K");
            var keys2 = HKDF.DeriveKey(innerSalt, innerInput, info2, 44);
            var innerKey = new byte[32];
            var innerIV = new byte[12];
            Array.Copy(keys2, 0, innerKey, 0, 32);
            Array.Copy(keys2, 32, innerIV, 0, 12);

            var lenInnerPlaintext = lenOuterPlaintext - innerCiphertextOffset - 32;
            var innerPlaintext = new byte[lenInnerPlaintext];
            ChaCha20Decrypt(outerPlaintext, innerCiphertextOffset + 32,
                lenInnerPlaintext, innerKey, innerIV, innerPlaintext);

            // Parse inner lease set
            var storeType = innerPlaintext[0];
            if (storeType == 3 || storeType == 7) // StandardLeaseSet2 or MetaLeaseSet2
            {
                var innerReader = new I2PBufferCursor(innerPlaintext, 1);
                var ls2 = new I2PLeaseSet2(innerReader);
                DecryptedLeaseSet = ls2;
                leaseSet = ls2;
                return true;
            }

            Logging.LogDebug($"I2PEncryptedLeaseSet: Unexpected inner type {storeType}");
            return false;
        }
        catch (Exception ex)
        {
            Logging.LogDebug($"I2PEncryptedLeaseSet: Decryption failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    ///     Legacy overload - decryption requires a BlindedPublicKey, not raw key material.
    /// </summary>
    public bool TryDecrypt(I2PByteBlock privateKey, out ILeaseSet leaseSet)
    {
        leaseSet = null;
        Logging.LogWarning("I2PEncryptedLeaseSet: Use TryDecrypt(BlindedPublicKey) overload");
        return false;
    }

    /// <summary>
    ///     Extract client authentication data from Layer 1 plaintext.
    ///     Returns the total auth data length consumed, or -1 on failure.
    ///     Sets innerInput to authCookie || subcredential || publishedTimestamp (68 bytes).
    /// </summary>
    private static int ExtractClientAuthData(
        byte[] buf, int offset, int len,
        byte[] clientSecret, byte[] subcredential36,
        out byte[] innerInput)
    {
        innerInput = null;
        if (len < 1) return -1;

        var authType = (byte)((buf[offset] >> 1) & 0x07); // bits 1-3: scheme 0=DH, 1=PSK
        var pos = 0;

        if (authType == 0) // DH
        {
            // ephemeral public key (32 bytes)
            var ephemeralPK = new byte[32];
            Array.Copy(buf, offset + pos, ephemeralPK, 0, 32);
            pos += 32;

            var numClients = (ushort)((buf[offset + pos] << 8) | buf[offset + pos + 1]);
            pos += 2;

            if (clientSecret != null && clientSecret.Length >= 32)
            {
                // Derive cpk_i from csk_i using X25519
                var cpk = X25519.GetPublicKey(clientSecret);
                var sharedSecret = X25519.ComputeSharedSecret(clientSecret, ephemeralPK);

                // authInput = sharedSecret || cpk_i || subcredential || publishedTimestamp
                var authInput = new byte[100];
                Array.Copy(sharedSecret, 0, authInput, 0, 32);
                Array.Copy(cpk, 0, authInput, 32, 32);
                Array.Copy(subcredential36, 0, authInput, 64, 36);

                var okm = HKDF.DeriveKey(ephemeralPK, authInput,
                    Encoding.ASCII.GetBytes("ELS2_XCA"), 52);

                // Search for matching cookie
                var authCookie = FindAuthCookie(buf, offset + pos, numClients, okm);
                if (authCookie != null)
                {
                    innerInput = new byte[68];
                    Array.Copy(authCookie, 0, innerInput, 0, 32);
                    Array.Copy(subcredential36, 0, innerInput, 32, 36);
                    pos += numClients * 40;
                    return pos;
                }
            }

            pos += numClients * 40;
            return -1;
        }
        else // PSK (authType == 1)
        {
            var authSalt = new byte[32];
            Array.Copy(buf, offset + pos, authSalt, 0, 32);
            pos += 32;

            var numClients = (ushort)((buf[offset + pos] << 8) | buf[offset + pos + 1]);
            pos += 2;

            if (clientSecret != null && clientSecret.Length >= 32)
            {
                var authInput = new byte[68];
                Array.Copy(clientSecret, 0, authInput, 0, 32);
                Array.Copy(subcredential36, 0, authInput, 32, 36);

                var okm = HKDF.DeriveKey(authSalt, authInput,
                    Encoding.ASCII.GetBytes("ELS2PSKA"), 52);

                var authCookie = FindAuthCookie(buf, offset + pos, numClients, okm);
                if (authCookie != null)
                {
                    innerInput = new byte[68];
                    Array.Copy(authCookie, 0, innerInput, 0, 32);
                    Array.Copy(subcredential36, 0, innerInput, 32, 36);
                    pos += numClients * 40;
                    return pos;
                }
            }

            pos += numClients * 40;
            return -1;
        }
    }

    /// <summary>
    ///     Search through auth client entries for a matching cookie.
    ///     Each entry is 40 bytes: 8 bytes client_id + 32 bytes encrypted_cookie.
    /// </summary>
    private static byte[] FindAuthCookie(byte[] buf, int offset, int numClients, byte[] okm)
    {
        // okm[0:8] = clientID, okm[8:40] = cookie_key, okm[40:52] = cookie_iv
        var expectedId = new byte[8];
        Array.Copy(okm, 0, expectedId, 0, 8);

        var cookieKey = new byte[32];
        Array.Copy(okm, 8, cookieKey, 0, 32);

        var cookieIV = new byte[12];
        Array.Copy(okm, 40, cookieIV, 0, 12);

        for (var i = 0; i < numClients; i++)
        {
            var entryOffset = offset + i * 40;
            var match = true;
            for (var j = 0; j < 8; j++)
                if (buf[entryOffset + j] != expectedId[j])
                {
                    match = false;
                    break;
                }

            if (match)
            {
                // Decrypt the cookie
                var encCookie = new byte[32];
                Array.Copy(buf, entryOffset + 8, encCookie, 0, 32);
                var cookie = new byte[32];
                ChaCha20Decrypt(encCookie, 0, 32, cookieKey, cookieIV, cookie);
                return cookie;
            }
        }

        return null;
    }

    /// <summary>
    ///     ChaCha20 stream cipher decryption (RFC 7539, no authentication tag).
    /// </summary>
    private static void ChaCha20Decrypt(byte[] input, int inputOffset, int length,
        byte[] key, byte[] iv, byte[] output)
    {
        var engine = new ChaCha7539Engine();
        engine.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
        engine.ProcessBytes(input, inputOffset, length, output, 0);
    }

    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    public void AddLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid, I2PDate enddate)
    {
        throw new NotSupportedException(
            "EncryptedLeaseSet does not support adding leases. Must decrypt first.");
    }

    public void RemoveLease(I2PIdentHash tunnelgw, I2PTunnelId tunnelid)
    {
        throw new NotSupportedException(
            "EncryptedLeaseSet does not support removing leases. Must decrypt first.");
    }

    public override string ToString()
    {
        return $"I2PEncryptedLeaseSet: BlindedKey {BlindedSigType}, " +
               $"Published {Published}, Expires {Expire - DateTime.UtcNow}, " +
               $"EncryptedSize {EncryptedData.Length} bytes, " +
               $"Decrypted: {DecryptedLeaseSet != null}";
    }
}