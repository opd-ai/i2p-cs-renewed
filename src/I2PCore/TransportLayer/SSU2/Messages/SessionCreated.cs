using System;
using I2PCore.Crypto;
using I2PCore.Utils;

namespace I2PCore.TransportLayer.SSU2.Messages;

/// <summary>
///     SSU2 Session Created (Handshake Message 2)
///     Noise XK pattern:
///     <- e, ee
///         Contains:
///         - Long header (32 bytes)
///         - Encrypted ephemeral key Y (32 bytes, obfuscated with ChaCha20)
///         - Encrypted payload ( variable)
/// </summary>
public class SessionCreated
{
    public SessionCreated()
    {
        Header = new SSU2Header
        {
            IsLongHeader = true,
            Type = SSU2Header.TYPE_SESSION_CREATED,
            Version = 2,
            NetId = 2
        };
    }

    public SSU2Header Header { get; set; }
    public byte[] EphemeralKey { get; set; } // Y, 32 bytes
    public byte[] EncryptedPayload { get; set; }
    public uint Timestamp { get; set; }
    public ushort PaddingLength { get; set; }
    public byte[] Padding { get; set; }

    public static SessionCreated Parse(I2PBufferCursor data, byte[] bobIntroKey, byte[] chainingKey, byte[] fullPacket)
    {
        var created = new SessionCreated();

        // For Session Created (Alice receives):
        // k_header_1 = bik (Bob's intro key)
        // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        // SSU2 spec lines 1255-1270
        var kHeader1 = bobIntroKey;
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);

        // Decrypt the first 16 bytes using IVs from packet end (bytes 0-15 only)
        SSU2HeaderEncryption.DecryptLongHeaderInPacket(fullPacket, 0, kHeader1, kHeader2);

        // Parse decrypted header from packet
        created.Header = SSU2Header.ParseLongHeader(new I2PBufferCursor(fullPacket));

        // Deobfuscate headerX: bytes 16-63 (srcConnID+token+ephKey) using a single 48-byte ChaCha20 keystream.
        // Per i2pd: ChaCha20(headerX, 48, kh2, zeroNonce, headerX)
        SSU2HeaderEncryption.ObfuscateHeaderX(fullPacket, 16, kHeader2);

        // Extract ephemeral key Y from bytes 32-63 (now deobfuscated)
        created.EphemeralKey = new byte[32];
        Array.Copy(fullPacket, 32, created.EphemeralKey, 0, 32);

        // Read encrypted payload (rest of packet)
        var remaining = fullPacket.Length - 64;
        created.EncryptedPayload = new byte[remaining];
        Array.Copy(fullPacket, 64, created.EncryptedPayload, 0, remaining);

        return created;
    }

    public byte[] ToByteArray(byte[] bobIntroKey, byte[] chainingKey, byte[] ephemeralKey, byte[] encryptedPayload)
    {
        // For Session Created (Bob sends):
        // k_header_1 = bik (Bob's intro key)
        // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
        // SSU2 spec lines 1255-1270
        var kHeader1 = bobIntroKey;
        var kHeader2 = SSU2HeaderEncryption.DeriveSessionCreatedHeaderKey(chainingKey);

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
        // Build options block for SessionCreated payload
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