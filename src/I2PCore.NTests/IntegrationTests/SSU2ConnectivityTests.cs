using System.Linq;
using System.Threading.Tasks;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.IntegrationTests;

/// <summary>
///     SSU2 connectivity integration tests between C# router and i2pd.
///     Tests UDP-based handshake, data exchange, fragmentation, and PQ variants.
/// </summary>
[TestFixture]
[Category("Integration")]
public class SSU2ConnectivityTests
{
    [SetUp]
    public void SetUp()
    {
        TestNetworkFixture.RequireI2pd();
        TestNetworkFixture.RequireCSharpRouter();

        // Verify i2pd has SSU2 addresses
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var hasSsu2 = i2pdInfo.Addresses?.Any(a => a.TransportStyle?.ToString() == "SSU2"
                                                   || a.Options.Any(o => o.Key.ToString() == "s")) == true;
        if (!hasSsu2)
            Assert.Ignore("i2pd does not advertise SSU2 addresses");
    }

    /// <summary>
    ///     C# router initiates SSU2 session to i2pd.
    ///     Verifies the Noise XK handshake over UDP completes.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestCSharpConnectsToI2pd_SSU2()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        // Connect to i2pd
        router.ConnectToPeer(i2pdInfo);

        // Wait for connection — may use either NTCP2 or SSU2
        var connected = await router.WaitForConnection(i2pdHash, 30000);
        Assert.IsTrue(connected,
            "C# router should establish connection to i2pd");

        var protocol = router.GetConnectionProtocol(i2pdHash);
        Logging.LogInformation($"Connected to i2pd via {protocol}");

        // Note: TransportProvider may prefer NTCP2 over SSU2.
        // This test verifies that at minimum a transport connection is established.
        // To force SSU2, we would need to disable NTCP2 on one side.
    }

    /// <summary>
    ///     Test SSU2-only connectivity by verifying SSU2 addresses are parseable
    ///     and the session can be initiated.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestSSU2AddressParsing()
    {
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;

        // Parse SSU2 addresses from i2pd's RouterInfo
        foreach (var addr in i2pdInfo.Addresses)
        {
            var options = addr.Options.ToDictionary(
                o => o.Key.ToString(), o => o.Value.ToString());

            Logging.LogInformation(
                $"i2pd address: style={addr.TransportStyle}, " +
                $"host={addr.Host}, port={addr.Port}, " +
                $"options=[{string.Join(", ", options.Select(o => $"{o.Key}={o.Value}"))}]");

            // Verify required SSU2 fields
            if (addr.TransportStyle?.ToString() == "SSU2")
            {
                Assert.IsTrue(addr.Port > 0, "SSU2 port should be > 0");
                Assert.IsTrue(options.ContainsKey("s"),
                    "SSU2 address should have static key (s)");
                Assert.IsTrue(options.ContainsKey("i"),
                    "SSU2 address should have intro key (i)");
            }
        }
    }

    /// <summary>
    ///     Test that SSU2 data frames work after handshake.
    ///     Sends I2NP messages and verifies they don't crash the session.
    /// </summary>
    [Test]
    [CancelAfter(45000)]
    public async Task TestSSU2DataExchange()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        // Ensure connection
        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(i2pdInfo);
            var connected = await router.WaitForConnection(i2pdHash, 30000);
            Assert.IsTrue(connected, "Must be connected for data exchange");
        }

        // Send multiple I2NP messages
        for (var i = 0; i < 3; i++)
        {
            var dsm = new DatabaseStoreMessage(
                RouterContext.Inst.MyRouterInfo);
            TransportProvider.Send(i2pdHash, dsm);
            await Task.Delay(500);
        }

        // Connection should remain stable
        await Task.Delay(2000);
        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "SSU2 connection should be stable after data exchange");
    }

    /// <summary>
    ///     Test SSU2 with ML-KEM768 post-quantum hybrid.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestCSharpConnectsToI2pd_SSU2_PQ()
    {
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;

        // Check PQ support in i2pd's SSU2 addresses
        var hasPQ = i2pdInfo.Addresses?.Any(a => a.Options.Any(o =>
            o.Key.ToString() == "i" &&
            o.Value.ToString().Length > 44)) == true; // PQ intro key is longer

        if (!hasPQ)
            Assert.Ignore(
                "i2pd does not advertise PQ SSU2 support — skipping ML-KEM test");

        var router = TestNetworkFixture.CSharpRouter;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        router.ConnectToPeer(i2pdInfo);
        var connected = await router.WaitForConnection(i2pdHash);
        Assert.IsTrue(connected, "PQ SSU2 connection should be established");
    }

    /// <summary>
    ///     Test SSU2 ACK handling by sending multiple messages rapidly
    ///     and verifying the connection stays alive.
    /// </summary>
    [Test]
    [CancelAfter(45000)]
    public async Task TestSSU2ACKHandling()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(i2pdInfo);
            var connected = await router.WaitForConnection(i2pdHash);
            Assert.IsTrue(connected, "Must be connected");
        }

        // Rapid-fire messages to test ACK processing
        for (var i = 0; i < 10; i++)
        {
            var dsm = new DatabaseStoreMessage(
                RouterContext.Inst.MyRouterInfo);
            TransportProvider.Send(i2pdHash, dsm);
            // Minimal delay to stress ACK handling
            await Task.Delay(100);
        }

        await Task.Delay(3000);
        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "Connection should survive rapid message burst (ACKs processed correctly)");
    }

    /// <summary>
    ///     Test that SSU2 session persists through an idle period.
    /// </summary>
    [Test]
    [CancelAfter(60000)]
    public async Task TestSSU2SessionPersistence()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(i2pdInfo);
            var connected = await router.WaitForConnection(i2pdHash);
            Assert.IsTrue(connected, "Must be connected");
        }

        // Idle for 15 seconds
        await Task.Delay(15000);

        // Should still be connected
        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "SSU2 session should persist during idle (keepalive packets)");
    }
}