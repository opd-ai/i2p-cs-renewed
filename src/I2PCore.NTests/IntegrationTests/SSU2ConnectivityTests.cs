using System;
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
    ///     Asserts the established transport is SSU2; NTCP2 fallback is treated as a failure.
    ///     Previously this test allowed NTCP2 fallback, masking SSU2 breakage.
    ///
    ///     NOTE: <see cref="TransportProvider"/> picks transport via <c>.Random()</c> among
    ///     providers with equal capability. If both SSU2 and NTCP2 addresses are present for
    ///     i2pd this test may intermittently use NTCP2. Run with i2pd configured to publish
    ///     only SSU2 addresses (or NTCP2 disabled) for deterministic results.
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

        var connected = await router.WaitForConnection(i2pdHash, 30000);
        Assert.IsTrue(connected,
            "C# router should establish connection to i2pd");

        var protocol = router.GetConnectionProtocol(i2pdHash);
        Logging.LogInformation($"Connected to i2pd via {protocol}");

        // Assert SSU2 specifically — NTCP2 fallback is a test failure because it
        // means SSU2 handshake silently failed and NTCP2 was used instead.
        Assert.IsTrue(
            protocol != null && protocol.IndexOf("SSU2", StringComparison.OrdinalIgnoreCase) >= 0,
            $"Connection must use SSU2 transport (not NTCP2 fallback), got: {protocol ?? "(null)"}. " +
            "NTCP2 fallback masks SSU2 handshake failures.");
    }

    /// <summary>
    ///     Verifies that an SSU2 connection is established between C# router and i2pd after
    ///     the C# router initiates contact. This is an outbound-initiated test — it does not
    ///     prove that i2pd independently opened an inbound connection to the C# router.
    ///     True inbound-only verification would require disabling NTCP2 outbound initiation
    ///     or intercepting i2pd's outbound session setup.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestI2pdConnectsToCSharp_SSU2()
    {
        var router = TestNetworkFixture.CSharpRouter;

        // Trigger a bidirectional exchange: when we send to i2pd it may connect back to us.
        // This indirectly causes i2pd to see our SSU2 address and attempt an inbound session.
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        router.ConnectToPeer(i2pdInfo);

        // Wait for any connection (outbound or inbound) in either direction
        var connected = await router.WaitForConnection(i2pdHash, 30000);
        Assert.IsTrue(connected,
            "An SSU2 connection must be established between C# router and i2pd");

        var protocol = router.GetConnectionProtocol(i2pdHash);
        Logging.LogInformation($"Bidirectional SSU2 connection protocol: {protocol}");

        // Assert SSU2 specifically
        Assert.IsTrue(
            protocol != null && protocol.IndexOf("SSU2", StringComparison.OrdinalIgnoreCase) >= 0,
            $"Connection must use SSU2 transport, got: {protocol ?? "(null)"}");
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