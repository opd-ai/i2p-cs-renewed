using System;
using I2PCore.Crypto;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Session Request (Handshake Message 1)
///     Noise XK pattern: -> e, es
///     Contains:
///     - Long header (32 bytes)
///     - Encrypted ephemeral key X (32 bytes, obfuscated with ChaCha20)
///     - Encrypted payload (variable)
/// </summary>
public class SessionRequest
{
    public const int MIN_PADDING = 0;
    public const int MAX_PADDING = 64;

    public SessionRequest()
    {
        Header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_SESSION_REQUEST,
            Version = 2,
            NetId = 2 // I2P mainnet
        };
    }

    public SSU2Header Header { get; set; }
    public byte[] EphemeralKey { get; set; } // X, 32 bytes (plaintext)
    public byte[] EncryptedPayload { get; set; } // From Noise
    public uint Timestamp { get; set; }
    public ushort PaddingLength { get; set; }
    public byte[] Padding { get; set; }

    public static SessionRequest Parse(I2PBufferCursor data, byte[] bobIntroKey, byte[] fullPacket)
    {
        var request = new SessionRequest();

        // For Session Request: k_header_1 = k_header_2 = Bob's intro key (NO derivation)
        // SSU2 spec lines 707-720
        var kHeader1 = bobIntroKey;
        var kHeader2 = bobIntroKey;

        // Decrypt the first 16 bytes using IVs from packet end (bytes 0-15 only)
        SSU2HeaderEncryption.DecryptLongHeaderInPacket(fullPacket, 0, kHeader1, kHeader2);

        // Deobfuscate headerX: bytes 16-63, which contains:
        //   srcConnId (bytes 16-23) | token (bytes 24-31) | ephKey (bytes 32-63)
        // A single 48-byte ChaCha20(introKey, zeroNonce) keystream is applied to all of bytes 16-63.
        // Per i2pd: ChaCha20(headerX, 48, introKey, zeroNonce, headerX)
        // Must be done BEFORE ParseLongHeader so SourceConnectionId (bytes 16-23) and Token (bytes 24-31)
        // are deobfuscated before being read.
        SSU2HeaderEncryption.ObfuscateHeaderX(fullPacket, 16, kHeader2);

        // Parse decrypted header from packet (bytes 0-31 are now fully plain)
        request.Header = SSU2Header.ParseLongHeader(new I2PBufferCursor(fullPacket));

        // Extract ephemeral key from bytes 32-63 (now deobfuscated)
        request.EphemeralKey = new byte[32];
        Array.Copy(fullPacket, 32, request.EphemeralKey, 0, 32);

        // Read encrypted payload (rest of the packet)
        var remaining = fullPacket.Length - 64;
        request.EncryptedPayload = new byte[remaining];
        Array.Copy(fullPacket, 64, request.EncryptedPayload, 0, remaining);

        return request;
    }

    public byte[] ToByteArray(byte[] bobIntroKey, byte[] ephemeralKey, byte[] encryptedPayload)
    {
        // For Session Request: k_header_1 = k_header_2 = Bob's intro key (NO derivation)
        // SSU2 spec lines 707-720
        var kHeader1 = bobIntroKey;
        var kHeader2 = bobIntroKey;

        // Build header (plaintext first)
        var header = Header.ToByteArray();

        // Build complete packet: long header (32 bytes) + plain ephKey (32 bytes) + payload.
        // Apply header encryption in two steps to match i2pd's layout exactly:
        //   1. Bytes  0-15: XOR with ChaCha20 masks derived from packet end.
        //   2. Bytes 16-63: single 48-byte ChaCha20(kHeader2, zeroIV) over srcConnID+token+ephKey.
        var padding = Padding ?? Array.Empty<byte>();
        var packet = new byte[header.Length + ephemeralKey.Length + encryptedPayload.Length + padding.Length];
        Array.Copy(header, 0, packet, 0, header.Length);
        Array.Copy(ephemeralKey, 0, packet, header.Length, ephemeralKey.Length);
        Array.Copy(encryptedPayload, 0, packet, header.Length + ephemeralKey.Length, encryptedPayload.Length);
        if (padding.Length > 0)
            Array.Copy(padding, 0, packet, header.Length + ephemeralKey.Length + encryptedPayload.Length,
                padding.Length);

        // Step 1: Encrypt bytes 0-15 using IVs from packet end
        SSU2HeaderEncryption.EncryptLongHeaderInPacket(packet, 0, kHeader1, kHeader2);

        // Step 2: Obfuscate headerX bytes 16-63 (srcConnID+token+ephKey) with a single 48-byte keystream
        SSU2HeaderEncryption.ObfuscateHeaderX(packet, 16, kHeader2);

        return packet;
    }

    public byte[] BuildPayload()
    {
        // Build options block for SessionRequest payload
        var payload = new I2PByteBlock(new byte[4096]);
        var writer = new I2PBufferCursor(payload);

        // Timestamp (4 bytes)
        writer.WriteUInt32BigEndian(Timestamp);

        // Padding length (2 bytes)
        writer.WriteUInt16BigEndian(PaddingLength);

        // Reserved (2 bytes)
        writer.WriteUInt16BigEndian(0);

        return payload.ToByteArray();
    }
}