using I2PCore.Crypto;
using I2PCore.Crypto.MLKEM;
using I2PCore.Crypto.Noise;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests;

[TestFixture]
public class NTCP2PQHandshakeTest
{
    [SetUp]
    public void Setup()
    {
        Logging.LogToDebug = true;
    }

    [TestCase(3, NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM512)]
    [TestCase(4, NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM768)]
    [TestCase(5, NoiseXK.PROTOCOL_NAME_NTCP2_MLKEM1024)]
    public void TestNTCP2PQHandshake(int pqVersion, string protocolName)
    {
        var (aliceStaticPriv, aliceStaticPub) = X25519.GenerateKeyPair();
        var (bobStaticPriv, bobStaticPub) = X25519.GenerateKeyPair();

        var alice = new NoiseXK(protocolName);
        alice.InitializeAsAlice(aliceStaticPriv, aliceStaticPub, bobStaticPub);

        var bob = new NoiseXK(protocolName);
        bob.InitializeAsBob(bobStaticPriv, bobStaticPub);

        // --- Message 1: Alice -> Bob (e, es, e1, p) ---
        alice.GenerateAliceEphemeralKeys();
        var aliceCipherKey1 = alice.PerformMessage1EphemeralAndES();

        // Alice generates ML-KEM keypair (e1)
        byte[] aliceKemPub, aliceKemPriv;
        if (pqVersion == 3) (aliceKemPub, aliceKemPriv) = MLKEM512.GenerateKeyPair();
        else if (pqVersion == 4) (aliceKemPub, aliceKemPriv) = MLKEM768.GenerateKeyPair();
        else (aliceKemPub, aliceKemPriv) = MLKEM1024.GenerateKeyPair();

        var msg1KemFrame = alice.EncryptHandshakeBlock(aliceCipherKey1, aliceKemPub);

        var msg1Payload = BufUtils.RandomBytes(16);
        var msg1EncPayload = alice.EncryptHandshakeBlock(aliceCipherKey1, msg1Payload);

        // Bob processes Message 1
        var bobCipherKey1 = bob.PerformProcessMessage1EphemeralAndES(alice.GetAliceEphemeralPublicKey());
        var bobRecoveredKemPub = bob.DecryptHandshakeBlock(bobCipherKey1, msg1KemFrame);
        Assert.IsTrue(BufUtils.Equal(aliceKemPub, bobRecoveredKemPub), "MLKEM public key mismatch");

        var bobRecoveredPayload1 = bob.DecryptHandshakeBlock(bobCipherKey1, msg1EncPayload);
        Assert.IsTrue(BufUtils.Equal(msg1Payload, bobRecoveredPayload1), "Msg 1 payload mismatch");

        // --- Message 2: Bob -> Alice (e, ee, ekem1, p) ---
        bob.GenerateBobEphemeralKeys();
        var bobCipherKey2 = bob.PerformMessage2EphemeralAndEE();

        // Bob encapsulates (ekem1)
        byte[] kemCiphertext, kemSharedSecret;
        if (pqVersion == 3) (kemCiphertext, kemSharedSecret) = MLKEM512.Encapsulate(bobRecoveredKemPub);
        else if (pqVersion == 4) (kemCiphertext, kemSharedSecret) = MLKEM768.Encapsulate(bobRecoveredKemPub);
        else (kemCiphertext, kemSharedSecret) = MLKEM1024.Encapsulate(bobRecoveredKemPub);

        var msg2KemFrame = bob.EncryptHandshakeBlock(bobCipherKey2, kemCiphertext);

        // Bob mixes PQ key and gets NEW cipher key for options
        var bobCipherKey2New = bob.MixKeyPQ(kemSharedSecret);
        bob.StoreMessage2CipherKey(bobCipherKey2); // For Part 1

        var msg2Payload = BufUtils.RandomBytes(16);
        var msg2EncPayload = bob.EncryptHandshakeBlock(bobCipherKey2New, msg2Payload);

        // Alice processes Message 2
        var aliceCipherKey2 = alice.PerformProcessMessage2EphemeralAndEE(bob.GetBobEphemeralPublicKey());
        var aliceRecoveredKemCT = alice.DecryptHandshakeBlock(aliceCipherKey2, msg2KemFrame);
        Assert.IsTrue(BufUtils.Equal(kemCiphertext, aliceRecoveredKemCT), "MLKEM ciphertext mismatch");

        // Alice decapsulates
        byte[] aliceRecoveredSharedSecret;
        if (pqVersion == 3) aliceRecoveredSharedSecret = MLKEM512.Decapsulate(aliceRecoveredKemCT, aliceKemPriv);
        else if (pqVersion == 4) aliceRecoveredSharedSecret = MLKEM768.Decapsulate(aliceRecoveredKemCT, aliceKemPriv);
        else aliceRecoveredSharedSecret = MLKEM1024.Decapsulate(aliceRecoveredKemCT, aliceKemPriv);

        Assert.IsTrue(BufUtils.Equal(kemSharedSecret, aliceRecoveredSharedSecret), "Shared secret mismatch");

        var aliceCipherKey2New = alice.MixKeyPQ(aliceRecoveredSharedSecret);
        alice.StoreMessage2CipherKey(aliceCipherKey2); // For Part 1
        var aliceRecoveredPayload2 = alice.DecryptHandshakeBlock(aliceCipherKey2New, msg2EncPayload);
        Assert.IsTrue(BufUtils.Equal(msg2Payload, aliceRecoveredPayload2), "Msg 2 payload mismatch");

        // --- Message 3: Part 1 (s) ---
        var msg3Part1 = alice.CreateMessage3Part1();
        var bobRecoveredStatic = bob.ProcessMessage3Part1(msg3Part1);
        Assert.IsTrue(BufUtils.Equal(aliceStaticPub, bobRecoveredStatic), "Static key mismatch");

        // --- Message 3: Part 2 (se, p) ---
        var msg3Payload = BufUtils.RandomBytes(32);
        var msg3Part2 = alice.CreateMessage3Part2(msg3Payload);
        var bobRecoveredPayload3 = bob.ProcessMessage3Part2(msg3Part2);
        Assert.IsTrue(BufUtils.Equal(msg3Payload, bobRecoveredPayload3), "Msg 3 payload mismatch");

        // --- Data Phase ---
        alice.Split(true);
        bob.Split(false);

        var data = BufUtils.RandomBytes(100);
        var encrypted = alice.EncryptData(data);
        var decrypted = bob.DecryptData(encrypted);
        Assert.IsTrue(BufUtils.Equal(data, decrypted), "Data phase mismatch");

        Logging.LogInformation($"NTCP2 PQ {pqVersion} handshake test passed");
    }
}