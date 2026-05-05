using System;
using System.Security.Cryptography;
using I2PCore.Crypto.MLKEM;
using Org.BouncyCastle.Crypto.Parameters;

namespace I2PCore.Crypto.Noise;

/// <summary>
///     Noise_IKhfselg2_25519+MLKEM512_ChaChaPoly_SHA256
///     IK pattern with hybrid forward secrecy:
///     - X25519 for initial DH
///     - ML-KEM-512/768/1024 for post-quantum KEM
///     - Elligator2 encoding for ephemeral keys
///     - ChaCha20-Poly1305 AEAD
///     - SHA-256 for hashing
///     Pattern:
///     <- s
///         ...
///         ->
///         e, es, s, ss, ekem1, payload
///         <- ekem2, payload
/// </summary>
public class NoiseIKhfs : NoiseHandshakeState
{
    public enum KEMVariant
    {
        MLKEM512,
        MLKEM768,
        MLKEM1024
    }

    private readonly KEMVariant kemVariant;
    private readonly bool isInitiator;

    private byte[] localKemSecretKey; // Alice's decap_key
    private byte[] localKemPublicKey; // Alice's encap_key (e1)
    private byte[] remoteKemPublicKey; // received by Bob
    private byte[] kemCiphertext; // ekem2 (Bob's response)

    public NoiseIKhfs(KEMVariant variant, bool initiator)
    {
        kemVariant = variant;
        isInitiator = initiator;

        var protocolName = variant switch
        {
            KEMVariant.MLKEM512 => "Noise_IKhfselg2_25519+MLKEM512_ChaChaPoly_SHA256",
            KEMVariant.MLKEM768 => "Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256",
            KEMVariant.MLKEM1024 => "Noise_IKhfselg2_25519+MLKEM1024_ChaChaPoly_SHA256",
            _ => throw new ArgumentException($"Unsupported KEM variant: {variant}")
        };

        Initialize(protocolName);
    }

    public static NoiseIKhfs CreateInitiator(
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        byte[] remoteStaticPublic,
        KEMVariant variant = KEMVariant.MLKEM512)
    {
        var noise = new NoiseIKhfs(variant, true);
        noise.LocalStaticPrivateKey = localStaticPrivate;
        noise.LocalStaticPublicKey = localStaticPublic;
        noise.RemoteStaticPublicKey = remoteStaticPublic;

        // Pattern <- s
        noise.MixHash(remoteStaticPublic);
        return noise;
    }

    public static NoiseIKhfs CreateResponder(
        byte[] localStaticPrivate,
        byte[] localStaticPublic,
        KEMVariant variant = KEMVariant.MLKEM512)
    {
        var noise = new NoiseIKhfs(variant, false);
        noise.LocalStaticPrivateKey = localStaticPrivate;
        noise.LocalStaticPublicKey = localStaticPublic;
        noise.RemoteStaticPublicKey = null;

        // Pattern <- s
        noise.MixHash(localStaticPublic);
        return noise;
    }

    /// <summary>
    ///     Message 1 (Alice to Bob): -> e, es, F, s, ss, p
    /// </summary>
    public (byte[] ephemeralPublic, byte[] encryptedKemPublicKey, byte[] encryptedStatic, byte[] encryptedPayload)
        WriteMessageA(byte[] payload)
    {
        if (!isInitiator) throw new InvalidOperationException("Must be initiator");

        // -> e
        var ephemeralEncoded = GenerateEphemeralKeyElligator2();

        // -> es
        PerformES(true);

        // -> F (Alice's ML-KEM public key)
        switch (kemVariant)
        {
            case KEMVariant.MLKEM512:
                (localKemPublicKey, localKemSecretKey) = MLKEM512.GenerateKeyPair();
                break;
            case KEMVariant.MLKEM768:
                (localKemPublicKey, localKemSecretKey) = MLKEM768.GenerateKeyPair();
                break;
            case KEMVariant.MLKEM1024:
                (localKemPublicKey, localKemSecretKey) = MLKEM1024.GenerateKeyPair();
                break;
            default:
                throw new ArgumentException();
        }
        var encryptedKemPublicKey = EncryptAndHash(localKemPublicKey);

        // -> s
        var encryptedStatic = SendStaticKey();

        // -> ss
        PerformSS();

        // -> p
        var encryptedPayload = EncryptAndHash(payload);

        return (ephemeralEncoded, encryptedKemPublicKey, encryptedStatic, encryptedPayload);
    }

    /// <summary>
    ///     Message 1 (Bob receiving from Alice): -> e, es, F, s, ss, p
    /// </summary>
    public (byte[] payload, byte[] remoteStaticKey, byte[] remoteKemPublicKey)
        ReadMessageA(
            byte[] ephemeralPublicEncoded,
            byte[] encryptedKemPublicKey,
            byte[] encryptedStatic,
            byte[] encryptedPayload)
    {
        if (isInitiator) throw new InvalidOperationException("Must be responder");

        // -> e
        ReceiveEphemeralKeyElligator2(ephemeralPublicEncoded);

        // -> es
        PerformES(false);

        // -> F
        remoteKemPublicKey = DecryptAndHash(encryptedKemPublicKey);

        // -> s
        ReceiveStaticKey(encryptedStatic);

        // -> ss
        PerformSS();

        // -> p
        var payload = DecryptAndHash(encryptedPayload);

        return (payload, RemoteStaticPublicKey, remoteKemPublicKey);
    }

    /// <summary>
    ///     Message 2 (Bob to Alice): <- e, ee, F, FF, se, [empty MAC], split, payload
    ///     Java I2P "hs2" format: handshake tokens produce the ephemeral + encrypted KEM ct +
    ///     empty MAC sections; then split() + HKDF("AttachPayloadKDF") derives the payload key.
    /// </summary>
    public (byte[] ephemeralPublic, byte[] encryptedKemCiphertext, byte[] emptySectionMac, byte[] handshakeMac, byte[] encryptedPayload)
        WriteMessageB(byte[] payload)
    {
        if (isInitiator) throw new InvalidOperationException("Must be responder");

        // <- e
        var ephemeralEncoded = GenerateEphemeralKeyElligator2();

        // <- ee
        PerformEE();

        // <- F, FF (Bob's ML-KEM ciphertext)
        byte[] ct, ss;
        switch (kemVariant)
        {
            case KEMVariant.MLKEM512:
                (ct, ss) = MLKEM512.Encapsulate(remoteKemPublicKey);
                break;
            case KEMVariant.MLKEM768:
                (ct, ss) = MLKEM768.Encapsulate(remoteKemPublicKey);
                break;
            case KEMVariant.MLKEM1024:
                (ct, ss) = MLKEM1024.Encapsulate(remoteKemPublicKey);
                break;
            default:
                throw new ArgumentException();
        }
        kemCiphertext = ct;

        // Encrypt and Hash ciphertext BEFORE mixing the shared secret
        var encryptedKemCiphertext = EncryptAndHash(kemCiphertext);

        // Now mix the shared secret (FF pattern)
        MixKey(ss);

        // <- consistency: empty section (like standard IK)
        var emptySectionMac = EncryptAndHash(Array.Empty<byte>());

        // <- se
        PerformSE(false);

        // Handshake MAC (empty data encrypted after all tokens)
        var handshakeMac = EncryptAndHash(Array.Empty<byte>());

        // Split to derive transport keys
        var (k1, k2, splitCk) = Split();
        // Responder: k2 = k_ba
        var k_ba = k2;

        // Capture handshake hash BEFORE we modify anything else
        var handshakeHash = Hash;

        // Derive payload key (Java: INFO_6 = "AttachPayloadKDF")
        var payloadKey = Crypto.HKDF.DeriveKey(k_ba, Array.Empty<byte>(),
            System.Text.Encoding.ASCII.GetBytes("AttachPayloadKDF"), 32);

        // Encrypt payload with derived key, handshake hash as AD
        var nonce = ChaCha20Poly1305.CreateNonce(0);
        var encryptedPayload = ChaCha20Poly1305.Encrypt(payloadKey, nonce, payload, handshakeHash);

        return (ephemeralEncoded, encryptedKemCiphertext, emptySectionMac, handshakeMac, encryptedPayload);
    }

    /// <summary>
    ///     Message 2 (Alice receiving from Bob): <- e, ee, F, FF, se, [empty MAC], split, payload
    ///     Java I2P "hs2" format: after handshake tokens and empty MAC, split() + HKDF derives payload key.
    /// </summary>
    public byte[] ReadMessageB(
        byte[] ephemeralPublicEncoded,
        byte[] encryptedKemCiphertext,
        byte[] emptySectionMac,
        byte[] handshakeMac,
        byte[] encryptedPayload)
    {
        if (!isInitiator) throw new InvalidOperationException("Must be initiator");

        // <- e
        ReceiveEphemeralKeyElligator2(ephemeralPublicEncoded);

        // <- ee
        PerformEE();

        // <- F, FF
        kemCiphertext = DecryptAndHash(encryptedKemCiphertext);

        // Now decapsulate and mix shared secret
        byte[] ss;
        switch (kemVariant)
        {
            case KEMVariant.MLKEM512:
                ss = MLKEM512.Decapsulate(kemCiphertext, localKemSecretKey);
                break;
            case KEMVariant.MLKEM768:
                ss = MLKEM768.Decapsulate(kemCiphertext, localKemSecretKey);
                break;
            case KEMVariant.MLKEM1024:
                ss = MLKEM1024.Decapsulate(kemCiphertext, localKemSecretKey);
                break;
            default:
                throw new ArgumentException();
        }
        MixKey(ss);

        // <- empty section
        DecryptAndHash(emptySectionMac);

        // <- se
        PerformSE(true);

        // Verify handshake MAC (empty data after all tokens)
        DecryptAndHash(handshakeMac);

        // Split to derive transport keys
        var (k1, k2, splitCk) = Split();
        // Initiator: k2 = k_ba
        var k_ba = k2;

        // Capture handshake hash
        var handshakeHash = Hash;

        // Derive payload key (Java: INFO_6 = "AttachPayloadKDF")
        var payloadKey = Crypto.HKDF.DeriveKey(k_ba, Array.Empty<byte>(),
            System.Text.Encoding.ASCII.GetBytes("AttachPayloadKDF"), 32);

        // Decrypt payload with derived key, handshake hash as AD
        var nonce = ChaCha20Poly1305.CreateNonce(0);
        var payload = ChaCha20Poly1305.Decrypt(payloadKey, nonce, encryptedPayload, handshakeHash);

        if (payload == null)
            throw new System.Security.Cryptography.CryptographicException("Hybrid NSR payload decryption failed");

        return payload;
    }

    public new (byte[] sendKey, byte[] receiveKey, byte[] ck) FinalizeHandshake()
    {
        var (k1, k2, ck) = Split();
        return isInitiator ? (k1, k2, ck) : (k2, k1, ck);
    }

    public byte[] GetChainingKey() => ChainingKey;
    public byte[] GetHandshakeHash() => Hash;

    public void Dispose()
    {
        Clear();
        if (localKemSecretKey != null) Array.Clear(localKemSecretKey, 0, localKemSecretKey.Length);
    }
}