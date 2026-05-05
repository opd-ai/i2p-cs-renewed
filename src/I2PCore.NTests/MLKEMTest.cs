using System.Linq;
using I2PCore.Crypto.MLKEM;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Unit tests for ML-KEM (CRYSTALS-Kyber) key encapsulation mechanism.
///     Covers MLKEM-512, MLKEM-768, and MLKEM-1024 per NIST FIPS 203.
///     All tests are offline (no network required).
/// </summary>
[TestFixture]
public class MLKEMTest
{
    // ------------------------------------------------------------------ //
    // MLKEM-512 (security level 1, AES-128 equivalent)
    // ------------------------------------------------------------------ //

    [Test]
    public void TestMLKEM512KeyPairSizes()
    {
        var (publicKey, secretKey) = MLKEM512.GenerateKeyPair();

        Assert.IsNotNull(publicKey, "MLKEM-512 public key should not be null");
        Assert.IsNotNull(secretKey, "MLKEM-512 secret key should not be null");
        Assert.AreEqual(MLKEM512.PublicKeyBytes, publicKey.Length,
            "MLKEM-512 public key should be 800 bytes (FIPS 203)");
        Assert.AreEqual(MLKEM512.SecretKeyBytes, secretKey.Length,
            "MLKEM-512 secret key should be 1632 bytes (FIPS 203)");
    }

    [Test]
    public void TestMLKEM512EncapsulationSizes()
    {
        var (publicKey, _) = MLKEM512.GenerateKeyPair();
        var (ciphertext, sharedSecret) = MLKEM512.Encapsulate(publicKey);

        Assert.IsNotNull(ciphertext, "MLKEM-512 ciphertext should not be null");
        Assert.IsNotNull(sharedSecret, "MLKEM-512 shared secret should not be null");
        Assert.AreEqual(MLKEM512.CiphertextBytes, ciphertext.Length,
            "MLKEM-512 ciphertext should be 768 bytes (FIPS 203)");
        Assert.AreEqual(MLKEM512.SharedSecretBytes, sharedSecret.Length,
            "MLKEM-512 shared secret should be 32 bytes (FIPS 203)");
    }

    [Test]
    public void TestMLKEM512RoundTrip()
    {
        var (publicKey, secretKey) = MLKEM512.GenerateKeyPair();
        var (ciphertext, encapsulatedSecret) = MLKEM512.Encapsulate(publicKey);
        var decapsulatedSecret = MLKEM512.Decapsulate(ciphertext, secretKey);

        Assert.IsNotNull(decapsulatedSecret, "Decapsulated secret should not be null");
        Assert.AreEqual(MLKEM512.SharedSecretBytes, decapsulatedSecret.Length,
            "Decapsulated secret should be 32 bytes");
        Assert.IsTrue(BufUtils.Equal(encapsulatedSecret, decapsulatedSecret),
            "Encapsulated and decapsulated shared secrets must be equal (MLKEM-512 round-trip)");
    }

    [Test]
    public void TestMLKEM512WrongCiphertextProducesImplicitRejection()
    {
        var (publicKey, secretKey) = MLKEM512.GenerateKeyPair();
        var (ciphertext, encapsulatedSecret) = MLKEM512.Encapsulate(publicKey);

        // Corrupt the ciphertext — FIPS 203 mandates implicit rejection (different but
        // deterministic secret) rather than an exception.
        var corrupted = ciphertext.ToArray();
        corrupted[0] ^= 0xFF;

        var rejectedSecret = MLKEM512.Decapsulate(corrupted, secretKey);

        Assert.IsNotNull(rejectedSecret,
            "Decapsulation with corrupted ciphertext should return implicit rejection secret, not throw");
        Assert.IsFalse(BufUtils.Equal(encapsulatedSecret, rejectedSecret),
            "Corrupted ciphertext should produce a different secret (implicit rejection)");
    }

    // ------------------------------------------------------------------ //
    // MLKEM-768 (security level 3, AES-192 equivalent)
    // ------------------------------------------------------------------ //

    [Test]
    public void TestMLKEM768KeyPairSizes()
    {
        var (publicKey, secretKey) = MLKEM768.GenerateKeyPair();

        Assert.IsNotNull(publicKey, "MLKEM-768 public key should not be null");
        Assert.IsNotNull(secretKey, "MLKEM-768 secret key should not be null");
        Assert.AreEqual(MLKEM768.PublicKeyBytes, publicKey.Length,
            "MLKEM-768 public key should be 1184 bytes (FIPS 203)");
        Assert.AreEqual(MLKEM768.SecretKeyBytes, secretKey.Length,
            "MLKEM-768 secret key should be 2400 bytes (FIPS 203)");
    }

    [Test]
    public void TestMLKEM768EncapsulationSizes()
    {
        var (publicKey, _) = MLKEM768.GenerateKeyPair();
        var (ciphertext, sharedSecret) = MLKEM768.Encapsulate(publicKey);

        Assert.IsNotNull(ciphertext, "MLKEM-768 ciphertext should not be null");
        Assert.IsNotNull(sharedSecret, "MLKEM-768 shared secret should not be null");
        Assert.AreEqual(MLKEM768.CiphertextBytes, ciphertext.Length,
            "MLKEM-768 ciphertext should be 1088 bytes (FIPS 203)");
        Assert.AreEqual(MLKEM768.SharedSecretBytes, sharedSecret.Length,
            "MLKEM-768 shared secret should be 32 bytes (FIPS 203)");
    }

    [Test]
    public void TestMLKEM768RoundTrip()
    {
        var (publicKey, secretKey) = MLKEM768.GenerateKeyPair();
        var (ciphertext, encapsulatedSecret) = MLKEM768.Encapsulate(publicKey);
        var decapsulatedSecret = MLKEM768.Decapsulate(ciphertext, secretKey);

        Assert.IsNotNull(decapsulatedSecret, "Decapsulated secret should not be null");
        Assert.AreEqual(MLKEM768.SharedSecretBytes, decapsulatedSecret.Length,
            "Decapsulated secret should be 32 bytes");
        Assert.IsTrue(BufUtils.Equal(encapsulatedSecret, decapsulatedSecret),
            "Encapsulated and decapsulated shared secrets must be equal (MLKEM-768 round-trip)");
    }

    [Test]
    public void TestMLKEM768WrongCiphertextProducesImplicitRejection()
    {
        var (publicKey, secretKey) = MLKEM768.GenerateKeyPair();
        var (ciphertext, encapsulatedSecret) = MLKEM768.Encapsulate(publicKey);

        var corrupted = ciphertext.ToArray();
        corrupted[0] ^= 0xFF;

        var rejectedSecret = MLKEM768.Decapsulate(corrupted, secretKey);

        Assert.IsNotNull(rejectedSecret,
            "Decapsulation with corrupted ciphertext should return implicit rejection secret, not throw");
        Assert.IsFalse(BufUtils.Equal(encapsulatedSecret, rejectedSecret),
            "Corrupted ciphertext should produce a different secret (implicit rejection)");
    }

    [Test]
    public void TestMLKEM768GetPublicKeyFromSecretKey()
    {
        var (publicKey, secretKey) = MLKEM768.GenerateKeyPair();

        var extractedPublicKey = MLKEM768.GetPublicKey(secretKey);

        Assert.IsNotNull(extractedPublicKey, "Extracted public key should not be null");
        Assert.AreEqual(MLKEM768.PublicKeyBytes, extractedPublicKey.Length,
            "Extracted public key should be 1184 bytes");
        Assert.IsTrue(BufUtils.Equal(publicKey, extractedPublicKey),
            "Public key extracted from secret key must match original public key");
    }

    [Test]
    public void TestMLKEM768TwoPartyExchange()
    {
        // Alice generates a key pair and publishes her public key
        var (alicePublicKey, aliceSecretKey) = MLKEM768.GenerateKeyPair();

        // Bob encapsulates to Alice — produces (ciphertext, sharedSecretBob)
        var (ciphertext, sharedSecretBob) = MLKEM768.Encapsulate(alicePublicKey);

        // Alice decapsulates — produces sharedSecretAlice
        var sharedSecretAlice = MLKEM768.Decapsulate(ciphertext, aliceSecretKey);

        // Both sides must agree on the same shared secret
        Assert.IsTrue(BufUtils.Equal(sharedSecretBob, sharedSecretAlice),
            "Alice and Bob must derive the same 32-byte shared secret (MLKEM-768 key agreement)");

        // Shared secrets must not be all-zero
        Assert.IsFalse(sharedSecretAlice.All(b => b == 0),
            "Shared secret must not be all-zero bytes");
    }

    // ------------------------------------------------------------------ //
    // MLKEM-1024 (security level 5, AES-256 equivalent)
    // ------------------------------------------------------------------ //

    [Test]
    public void TestMLKEM1024KeyPairSizes()
    {
        var (publicKey, secretKey) = MLKEM1024.GenerateKeyPair();

        Assert.IsNotNull(publicKey, "MLKEM-1024 public key should not be null");
        Assert.IsNotNull(secretKey, "MLKEM-1024 secret key should not be null");
        Assert.AreEqual(MLKEM1024.PublicKeyBytes, publicKey.Length,
            "MLKEM-1024 public key should be 1568 bytes (FIPS 203)");
        Assert.AreEqual(MLKEM1024.SecretKeyBytes, secretKey.Length,
            "MLKEM-1024 secret key should be 3168 bytes (FIPS 203)");
    }

    [Test]
    public void TestMLKEM1024EncapsulationSizes()
    {
        var (publicKey, _) = MLKEM1024.GenerateKeyPair();
        var (ciphertext, sharedSecret) = MLKEM1024.Encapsulate(publicKey);

        Assert.IsNotNull(ciphertext, "MLKEM-1024 ciphertext should not be null");
        Assert.IsNotNull(sharedSecret, "MLKEM-1024 shared secret should not be null");
        Assert.AreEqual(MLKEM1024.CiphertextBytes, ciphertext.Length,
            "MLKEM-1024 ciphertext should be 1568 bytes (FIPS 203)");
        Assert.AreEqual(MLKEM1024.SharedSecretBytes, sharedSecret.Length,
            "MLKEM-1024 shared secret should be 32 bytes (FIPS 203)");
    }

    [Test]
    public void TestMLKEM1024RoundTrip()
    {
        var (publicKey, secretKey) = MLKEM1024.GenerateKeyPair();
        var (ciphertext, encapsulatedSecret) = MLKEM1024.Encapsulate(publicKey);
        var decapsulatedSecret = MLKEM1024.Decapsulate(ciphertext, secretKey);

        Assert.IsNotNull(decapsulatedSecret, "Decapsulated secret should not be null");
        Assert.AreEqual(MLKEM1024.SharedSecretBytes, decapsulatedSecret.Length,
            "Decapsulated secret should be 32 bytes");
        Assert.IsTrue(BufUtils.Equal(encapsulatedSecret, decapsulatedSecret),
            "Encapsulated and decapsulated shared secrets must be equal (MLKEM-1024 round-trip)");
    }

    // ------------------------------------------------------------------ //
    // Cross-instance isolation
    // ------------------------------------------------------------------ //

    [Test]
    public void TestMLKEM768DifferentKeyPairsProduceDifferentSecrets()
    {
        var (pk1, sk1) = MLKEM768.GenerateKeyPair();
        var (pk2, sk2) = MLKEM768.GenerateKeyPair();

        // Encapsulate to pk1, try to decapsulate with sk2 — must produce a different secret
        var (ciphertext, secret1) = MLKEM768.Encapsulate(pk1);
        var rejectedSecret = MLKEM768.Decapsulate(ciphertext, sk2);

        Assert.IsFalse(BufUtils.Equal(secret1, rejectedSecret),
            "Decapsulating with the wrong secret key must not recover the original shared secret");
    }

    [Test]
    public void TestMLKEM768MultipleEncapsulationsAreIndependent()
    {
        var (publicKey, secretKey) = MLKEM768.GenerateKeyPair();

        var (ct1, ss1) = MLKEM768.Encapsulate(publicKey);
        var (ct2, ss2) = MLKEM768.Encapsulate(publicKey);

        // Each encapsulation produces a fresh random shared secret
        Assert.IsFalse(BufUtils.Equal(ss1, ss2),
            "Each encapsulation should produce an independent random shared secret");

        // But each can be decapsulated correctly
        Assert.IsTrue(BufUtils.Equal(ss1, MLKEM768.Decapsulate(ct1, secretKey)),
            "First encapsulation must decapsulate correctly");
        Assert.IsTrue(BufUtils.Equal(ss2, MLKEM768.Decapsulate(ct2, secretKey)),
            "Second encapsulation must decapsulate correctly");
    }
}
