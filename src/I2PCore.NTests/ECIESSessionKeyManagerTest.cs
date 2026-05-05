using System;
using System.Linq;
using I2PCore.Crypto;
using I2PCore.Data;
using I2PCore.SessionLayer.ECIES;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

/// <summary>
///     Unit tests for ECIESSessionKeyManager.
///     Covers session tag generation, existing session tag lookup,
///     and new session message round-trip (offline — no network required).
/// </summary>
[TestFixture]
public class ECIESSessionKeyManagerTest
{
    private static (I2PDestination destination, byte[] staticPrivKey, byte[] staticPubKey)
        CreateTestDestination()
    {
        // Generate a fresh X25519 static key pair
        var cert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var priv = new I2PPrivateKey(cert);
        var pub = new I2PPublicKey(priv);

        // Signing key (EdDSA is the lightest to generate)
        var signingCert = new I2PCertificate(I2PSigningKey.SigningKeyTypes.EdDsaSha512Ed25519);
        var privSigning = new I2PSigningPrivateKey(signingCert);
        var pubSigning = new I2PSigningPublicKey(privSigning);

        var destination = new I2PDestination(pub, pubSigning);

        var staticPrivKey = priv.ToByteArray();   // 32 bytes
        var staticPubKey = pub.ToByteArray();      // 32 bytes

        return (destination, staticPrivKey, staticPubKey);
    }

    // ------------------------------------------------------------------
    // Constructor validation
    // ------------------------------------------------------------------

    [Test]
    public void TestConstructor_ValidKeys_DoesNotThrow()
    {
        var (dest, privKey, pubKey) = CreateTestDestination();

        Assert.DoesNotThrow(() =>
        {
            var _ = new ECIESSessionKeyManager(dest, privKey, pubKey);
        }, "ECIESSessionKeyManager constructor should succeed with valid 32-byte X25519 keys");
    }

    [Test]
    public void TestConstructor_NullDestination_Throws()
    {
        var (_, privKey, pubKey) = CreateTestDestination();

        Assert.Throws<ArgumentNullException>(() =>
        {
            var _ = new ECIESSessionKeyManager(null, privKey, pubKey);
        }, "Null localDestination should throw ArgumentNullException");
    }

    [Test]
    public void TestConstructor_WrongPrivateKeyLength_Throws()
    {
        var (dest, _, pubKey) = CreateTestDestination();
        var badKey = new byte[16]; // should be 32

        Assert.Throws<ArgumentException>(() =>
        {
            var _ = new ECIESSessionKeyManager(dest, badKey, pubKey);
        }, "Private key of wrong length should throw ArgumentException");
    }

    [Test]
    public void TestConstructor_WrongPublicKeyLength_Throws()
    {
        var (dest, privKey, _) = CreateTestDestination();
        var badKey = new byte[16]; // should be 32

        Assert.Throws<ArgumentException>(() =>
        {
            var _ = new ECIESSessionKeyManager(dest, privKey, badKey);
        }, "Public key of wrong length should throw ArgumentException");
    }

    // ------------------------------------------------------------------
    // LocalStaticPublicKey accessor
    // ------------------------------------------------------------------

    [Test]
    public void TestLocalStaticPublicKey_MatchesProvidedKey()
    {
        var (dest, privKey, pubKey) = CreateTestDestination();
        var skm = new ECIESSessionKeyManager(dest, privKey, pubKey);

        Assert.IsTrue(BufUtils.Equal(pubKey, skm.LocalStaticPublicKey),
            "LocalStaticPublicKey should equal the key passed to the constructor");
    }

    // ------------------------------------------------------------------
    // CreateNewSession — tag generation
    // ------------------------------------------------------------------

    [Test]
    public void TestCreateNewSession_ReturnsNonEmptyMessage()
    {
        var (aliceDest, alicePriv, alicePub) = CreateTestDestination();
        var (bobDest, bobPriv, bobPub) = CreateTestDestination();

        var aliceSkm = new ECIESSessionKeyManager(aliceDest, alicePriv, alicePub);

        // Construct a public key wrapper for Bob's static key
        var bobCert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var bobPubKey = new I2PPublicKey(new I2PPrivateKey(bobCert));
        // Use actual Bob pub key bytes by reconstructing from raw bytes
        var bobPubKeyFromBytes = CreatePublicKeyFromBytes(bobPub, bobCert);

        var payload = BufUtils.RandomBytes(32);

        var message = aliceSkm.CreateNewSession(
            bobDest.IdentHash,
            bobPubKeyFromBytes,
            payload);

        Assert.IsNotNull(message, "CreateNewSession should return a non-null message");
        Assert.IsTrue(message.Length > 0, "CreateNewSession should return a non-empty message");
        Assert.IsTrue(message.Length >= 48,
            "ECIES new session message should be at least 48 bytes (ephemeral + payload + MAC)");
    }

    [Test]
    public void TestCreateNewSession_SameRemote_ReturnsCachedMessage()
    {
        var (aliceDest, alicePriv, alicePub) = CreateTestDestination();
        var (bobDest, bobPriv, bobPub) = CreateTestDestination();

        var aliceSkm = new ECIESSessionKeyManager(aliceDest, alicePriv, alicePub);

        var bobCert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var bobPubKeyFromBytes = CreatePublicKeyFromBytes(bobPub, bobCert);
        var payload = BufUtils.RandomBytes(32);

        // First call
        var msg1 = aliceSkm.CreateNewSession(bobDest.IdentHash, bobPubKeyFromBytes, payload);
        // Second call with same remote — should return cached message (idempotent)
        var msg2 = aliceSkm.CreateNewSession(bobDest.IdentHash, bobPubKeyFromBytes, payload);

        Assert.IsTrue(BufUtils.Equal(msg1, msg2),
            "Repeated CreateNewSession for the same remote should return the cached message");
    }

    [Test]
    public void TestCreateNewSession_NullRemoteHash_Throws()
    {
        var (aliceDest, alicePriv, alicePub) = CreateTestDestination();
        var (_, _, bobPub) = CreateTestDestination();
        var aliceSkm = new ECIESSessionKeyManager(aliceDest, alicePriv, alicePub);

        var bobCert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var bobPubKeyFromBytes = CreatePublicKeyFromBytes(bobPub, bobCert);

        Assert.Throws<ArgumentNullException>(() =>
        {
            aliceSkm.CreateNewSession(null, bobPubKeyFromBytes, BufUtils.RandomBytes(32));
        }, "Null remoteHash should throw ArgumentNullException");
    }

    // ------------------------------------------------------------------
    // SessionCounts
    // ------------------------------------------------------------------

    [Test]
    public void TestSessionCounts_InitiallyZero()
    {
        var (dest, privKey, pubKey) = CreateTestDestination();
        var skm = new ECIESSessionKeyManager(dest, privKey, pubKey);

        var (inbound, outbound) = skm.SessionCounts;
        Assert.AreEqual(0, inbound + outbound,
            "A fresh ECIESSessionKeyManager should have zero sessions");
    }

    [Test]
    public void TestSessionCounts_AfterCreateNewSession_NonZero()
    {
        var (aliceDest, alicePriv, alicePub) = CreateTestDestination();
        var (bobDest, _, bobPub) = CreateTestDestination();
        var aliceSkm = new ECIESSessionKeyManager(aliceDest, alicePriv, alicePub);

        var bobCert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var bobPubKeyFromBytes = CreatePublicKeyFromBytes(bobPub, bobCert);

        aliceSkm.CreateNewSession(bobDest.IdentHash, bobPubKeyFromBytes, BufUtils.RandomBytes(32));

        var (inbound, outbound) = aliceSkm.SessionCounts;
        Assert.AreEqual(0, inbound,
            "Before handshake completes there should be no established (inbound) sessions");
        Assert.Greater(outbound, 0,
            "CreateNewSession should create at least one pending (outbound) session entry");
    }

    // ------------------------------------------------------------------
    // Full handshake round-trip (standard X25519 IK)
    // ------------------------------------------------------------------

    [Test]
    public void TestNewSessionRoundTrip_PayloadDelivered()
    {
        // Alice (initiator) and Bob (responder) both have ECIESSessionKeyManagers.
        var (aliceDest, alicePriv, alicePub) = CreateTestDestination();
        var (bobDest, bobPriv, bobPub) = CreateTestDestination();

        var aliceSkm = new ECIESSessionKeyManager(aliceDest, alicePriv, alicePub);
        var bobSkm = new ECIESSessionKeyManager(bobDest, bobPriv, bobPub);

        // Wrap Bob's public key so Alice can address him
        var bobCert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var bobPubKeyFromBytes = CreatePublicKeyFromBytes(bobPub, bobCert);

        // Step 1: Alice creates new session message
        var alicePayload = BufUtils.RandomBytes(128);
        var messageA = aliceSkm.CreateNewSession(bobDest.IdentHash, bobPubKeyFromBytes, alicePayload);

        Assert.IsNotNull(messageA, "Alice's new session message must not be null");
        Assert.IsTrue(messageA.Length > 48, "Alice's message must be non-trivial in size");

        // Step 2: Bob processes Message A
        var bobReplyPayload = BufUtils.RandomBytes(64);
        (var extractedPayload, var messageB) = bobSkm.ProcessNewSession(messageA, bobReplyPayload);

        Assert.IsNotNull(extractedPayload, "Bob should extract Alice's payload");
        Assert.IsTrue(BufUtils.Equal(alicePayload, extractedPayload),
            "Bob should recover Alice's exact payload from Message A");
        Assert.IsNotNull(messageB, "Bob must produce a reply (Message B)");
        Assert.IsTrue(messageB.Length > 0, "Bob's reply must not be empty");

        // Step 3: Alice processes Message B (Bob's reply)
        var replyPayload = aliceSkm.ProcessNewSessionReply(bobDest.IdentHash, messageB);

        Assert.IsNotNull(replyPayload, "Alice should extract Bob's reply payload");
        Assert.IsTrue(BufUtils.Equal(bobReplyPayload, replyPayload),
            "Alice should recover Bob's exact reply payload from Message B");
    }

    [Test]
    public void TestNewSession_BobHasInboundTagsAfterHandshake()
    {
        var (aliceDest, alicePriv, alicePub) = CreateTestDestination();
        var (bobDest, bobPriv, bobPub) = CreateTestDestination();

        var aliceSkm = new ECIESSessionKeyManager(aliceDest, alicePriv, alicePub);
        var bobSkm = new ECIESSessionKeyManager(bobDest, bobPriv, bobPub);

        var bobCert = new I2PCertificate(I2PKeyType.KeyTypes.X25519);
        var bobPubKeyFromBytes = CreatePublicKeyFromBytes(bobPub, bobCert);

        var messageA = aliceSkm.CreateNewSession(
            bobDest.IdentHash, bobPubKeyFromBytes, BufUtils.RandomBytes(32));

        // Bob processes Message A — this calls CreateNewSessionReply internally,
        // which sets _sendKey making the session IsEstablished.
        bobSkm.ProcessNewSession(messageA, BufUtils.RandomBytes(32));

        // After processing Message A, Bob's session must be established (inbound count > 0)
        // because CreateNewSessionReply sets the send key within ProcessNewSession.
        var (inbound, _) = bobSkm.SessionCounts;
        Assert.Greater(inbound, 0,
            "ProcessNewSession must create an established inbound session entry on Bob's side");
    }

    // ------------------------------------------------------------------
    // ProcessMessage routing via session tag
    // ------------------------------------------------------------------

    [Test]
    public void TestProcessMessage_NullMessage_Throws()
    {
        var (dest, privKey, pubKey) = CreateTestDestination();
        var skm = new ECIESSessionKeyManager(dest, privKey, pubKey);

        Assert.Throws<ArgumentNullException>(() =>
        {
            skm.ProcessMessage(null);
        }, "ProcessMessage with null should throw ArgumentNullException");
    }

    [Test]
    public void TestProcessMessage_UnknownTag_ReturnsFail()
    {
        var (dest, privKey, pubKey) = CreateTestDestination();
        var skm = new ECIESSessionKeyManager(dest, privKey, pubKey);

        // Random 16-byte message with unknown tag bytes — should not throw,
        // should return a failure result
        var randomMessage = BufUtils.RandomBytes(128);
        ProcessedDestinationMessage? result = null;

        Assert.DoesNotThrow(() =>
        {
            result = skm.ProcessMessage(randomMessage);
        }, "ProcessMessage with an unknown tag should not throw, only fail gracefully");

        Assert.IsNotNull(result, "ProcessMessage must always return a result object");
        Assert.IsFalse(result!.Success,
            "ProcessMessage with unrecognized content should set Success=false");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// <summary>
    ///     Reconstructs an I2PPublicKey from raw 32-byte X25519 key bytes.
    ///     The I2PPublicKey.Key field must hold the 32-byte X25519 public key.
    /// </summary>
    private static I2PPublicKey CreatePublicKeyFromBytes(byte[] rawPubKeyBytes, I2PCertificate cert)
    {
        // I2PPublicKey has a constructor that reads from a buffer cursor.
        // We write the raw bytes into a cursor-accessible buffer.
        var cursor = new I2PBufferCursor(rawPubKeyBytes, 0);
        return new I2PPublicKey(cursor, cert);
    }
}
