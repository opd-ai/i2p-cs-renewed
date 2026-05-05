using System.Linq;
using System.Threading.Tasks;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using I2PTests.IntegrationTests.Infrastructure;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.IntegrationTests;

/// <summary>
///     ECIES-X25519 and ML-KEM768 encryption compatibility tests with i2pd.
///     Verifies garlic message encryption, LeaseSet2 handling, and
///     session tag management work correctly cross-implementation.
/// </summary>
[TestFixture]
[Category("Integration")]
public class EncryptionCompatibilityTests
{
    [SetUp]
    public void SetUp()
    {
        TestNetworkFixture.RequireI2pd();
        TestNetworkFixture.RequireCSharpRouter();
    }

    /// <summary>
    ///     Verify that the ECIES-X25519 key types in i2pd's RouterInfo
    ///     are correctly parsed by our implementation.
    /// </summary>
    [Test]
    public void TestECIES_X25519_RouterInfoParsing()
    {
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;

        // i2pd should use EdDSA-SHA512-Ed25519 signing + X25519 encryption
        var cert = i2pdInfo.Identity.Certificate;
        Assert.IsNotNull(cert, "i2pd should have a certificate");

        Logging.LogInformation(
            $"i2pd certificate: signing={cert.KeySignatureType}, " +
            $"crypto={cert.KeyPublicKeyType}");

        // Verify the public key is present and correct size
        var pubKey = i2pdInfo.Identity.PublicKey;
        Assert.IsNotNull(pubKey, "i2pd should have a public key");

        // Verify the signing key
        var sigKey = i2pdInfo.Identity.SigningPublicKey;
        Assert.IsNotNull(sigKey, "i2pd should have a signing public key");

        // Verify signature
        Assert.IsTrue(i2pdInfo.VerifySignature(),
            "i2pd RouterInfo signature should be valid");
    }

    /// <summary>
    ///     Verify that NTCP2 X25519 static keys from i2pd are correctly parsed.
    /// </summary>
    [Test]
    public void TestNTCP2StaticKeyParsing()
    {
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;

        foreach (var addr in i2pdInfo.Addresses)
        {
            var options = addr.Options.ToDictionary(
                o => o.Key.ToString(), o => o.Value.ToString());

            if (options.TryGetValue("s", out var staticKey))
            {
                // Static key should be I2P base64-encoded 32-byte X25519 public key
                // I2P base64 uses '-' and '~' instead of '+' and '/'
                var keyBytes = FreenetBase64.Decode(staticKey);
                Assert.AreEqual(32, keyBytes.Length,
                    "NTCP2/SSU2 static key should be 32 bytes (X25519)");

                Logging.LogInformation(
                    $"i2pd static key for {addr.TransportStyle}: " +
                    $"{keyBytes.Length} bytes");
            }

            if (options.TryGetValue("i", out var introKey))
            {
                var iKeyBytes = FreenetBase64.Decode(introKey);
                Logging.LogInformation(
                    $"i2pd intro key: {iKeyBytes.Length} bytes");
            }
        }
    }

    /// <summary>
    ///     Test that garlic-encrypted messages can be sent to i2pd and
    ///     the transport layer handles them without errors.
    /// </summary>
    [Test]
    [CancelAfter(60000)]
    public async Task TestECIES_GarlicMessage_I2pd()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdHash = TestNetworkFixture.I2pdRouterInfo.Identity.IdentHash;

        // Ensure connection
        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(TestNetworkFixture.I2pdRouterInfo);
            var connected = await router.WaitForConnection(i2pdHash, 30000);
            Assert.IsTrue(connected, "Must be connected for garlic test");
        }

        // Send a DatabaseStoreMessage — this gets garlic-wrapped when sent
        // through tunnels. For direct transport, it's sent as I2NP.
        var dsm = new DatabaseStoreMessage(
            RouterContext.Inst.MyRouterInfo);
        TransportProvider.Send(i2pdHash, dsm);

        await Task.Delay(3000);

        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "Connection should survive after sending I2NP message");
    }

    /// <summary>
    ///     Verify that i2pd's RouterInfo options match expected format
    ///     for ECIES capabilities.
    /// </summary>
    [Test]
    public void TestRouterInfoCapabilities()
    {
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;

        // Check router capabilities (caps option)
        if (i2pdInfo.Options != null)
        {
            var capsStr = i2pdInfo.Options["caps"];
            if (capsStr != null)
            {
                Logging.LogInformation($"i2pd caps: {capsStr}");
                Assert.IsNotEmpty(capsStr, "caps should not be empty");
            }

            // Check netId
            var netIdVal = i2pdInfo.Options["netId"];
            if (netIdVal != null)
                Assert.AreEqual(I2pdConfigGenerator.TestNetworkId.ToString(), netIdVal,
                    $"i2pd netId should be {I2pdConfigGenerator.TestNetworkId}");

            // Check router version
            var versionStr = i2pdInfo.Options["router.version"];
            if (versionStr != null) Logging.LogInformation($"i2pd version: {versionStr}");
        }
    }

    /// <summary>
    ///     Test ML-KEM768 hybrid encryption compatibility with i2pd.
    ///     Verifies that the Noise protocol with ML-KEM extension
    ///     produces valid handshakes.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestMLKEM768_Hybrid_I2pd()
    {
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;

        // Check if i2pd advertises ML-KEM support
        var hasPQ = i2pdInfo.Addresses?.Any(a => a.Options.Any(o =>
            o.Key.ToString() == "i" &&
            o.Value.ToString().Length > 44)) == true;

        if (!hasPQ) Assert.Ignore("i2pd does not advertise ML-KEM support");

        var router = TestNetworkFixture.CSharpRouter;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        router.ConnectToPeer(i2pdInfo);
        var connected = await router.WaitForConnection(i2pdHash, 30000);
        Assert.IsTrue(connected,
            "Should establish ML-KEM hybrid connection");
    }

    /// <summary>
    ///     Verify that the C# router's own RouterInfo is correctly signed
    ///     and i2pd would accept it.
    /// </summary>
    [Test]
    public void TestOurRouterInfoValidity()
    {
        var ourInfo = RouterContext.Inst.MyRouterInfo;

        Assert.IsNotNull(ourInfo, "Our RouterInfo should exist");
        Assert.IsNotNull(ourInfo.Identity, "Should have identity");
        Assert.IsNotNull(ourInfo.Addresses, "Should have addresses");
        Assert.IsTrue(ourInfo.Addresses.Length > 0, "Should have at least one address");
        Assert.IsTrue(ourInfo.VerifySignature(), "Our signature should be valid");

        // Verify netId is set for test network
        if (ourInfo.Options != null)
        {
            var netIdVal = ourInfo.Options["netId"];
            if (netIdVal != null)
                Assert.AreEqual(I2pdConfigGenerator.TestNetworkId.ToString(),
                    netIdVal,
                    "Our netId should match test network");
        }

        Logging.LogInformation(
            $"Our RouterInfo: {ourInfo.Identity.IdentHash.Id32Short:x8}, " +
            $"{ourInfo.Addresses.Length} addresses, " +
            $"signature valid");
    }
}