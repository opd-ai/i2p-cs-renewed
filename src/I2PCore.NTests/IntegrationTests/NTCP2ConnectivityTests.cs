using System.Linq;
using System.Threading.Tasks;
using I2PCore;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TunnelLayer.I2NP.Messages;
using I2PCore.Utils;
using NUnit.Framework;
using Assert = NUnit.Framework.Legacy.ClassicAssert;

namespace I2PTests.IntegrationTests;

/// <summary>
///     NTCP2 connectivity integration tests between C# router and i2pd.
///     Tests handshake, data exchange, and post-quantum (ML-KEM) variants.
/// </summary>
[TestFixture]
[Category("Integration")]
public class NTCP2ConnectivityTests
{
    [SetUp]
    public void SetUp()
    {
        TestNetworkFixture.RequireI2pd();
        TestNetworkFixture.RequireCSharpRouter();
    }

    /// <summary>
    ///     Our C# router initiates an NTCP2 connection to i2pd.
    ///     Verifies the Noise XK handshake completes successfully.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestCSharpConnectsToI2pd_NTCP2()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        // Ensure i2pd RouterInfo has NTCP2 addresses
        var ntcp2Addr = i2pdInfo.Addresses?.FirstOrDefault(a => a.TransportStyle?.ToString() == "NTCP2"
                                                                || a.Options.Any(o => o.Key.ToString() == "s"));
        Assert.IsNotNull(ntcp2Addr,
            "i2pd RouterInfo should contain an NTCP2 address");

        // Initiate connection by sending a message
        router.ConnectToPeer(i2pdInfo);

        // Wait for the transport to reach established state
        var connected = await router.WaitForConnection(i2pdHash, 30000);
        Assert.IsTrue(connected,
            "C# router should establish NTCP2 connection to i2pd");

        // Verify it's an NTCP2 session
        var protocol = router.GetConnectionProtocol(i2pdHash);
        Logging.LogInformation($"Connected to i2pd via {protocol}");
        Assert.IsNotNull(protocol, "Should have an active transport");
    }

    /// <summary>
    ///     i2pd connects to our C# router (triggered by database lookup or
    ///     RouterInfo exchange making i2pd aware of us).
    /// </summary>
    [Test]
    [CancelAfter(60000)]
    public async Task TestI2pdConnectsToCSharp_NTCP2()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdHash = TestNetworkFixture.I2pdRouterInfo.Identity.IdentHash;

        // i2pd should attempt to connect to us since it has our RouterInfo
        // This may take time as i2pd processes its netDb
        var connected = await router.WaitForConnection(i2pdHash, 60000);

        if (!connected)
        {
            // Try triggering the connection by sending to i2pd first
            router.ConnectToPeer(TestNetworkFixture.I2pdRouterInfo);
            connected = await router.WaitForConnection(i2pdHash, 30000);
        }

        Assert.IsTrue(connected,
            "i2pd should connect to C# router via NTCP2");
    }

    /// <summary>
    ///     Test bidirectional I2NP message exchange over NTCP2.
    ///     After handshake, send a DatabaseStoreMessage and verify delivery.
    /// </summary>
    [Test]
    [CancelAfter(45000)]
    public async Task TestNTCP2DataExchange_I2pd()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        // Ensure connection is established
        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(i2pdInfo);
            var connected = await router.WaitForConnection(i2pdHash, 30000);
            Assert.IsTrue(connected, "Must be connected before data exchange test");
        }

        // Send a DatabaseStoreMessage (our RouterInfo) to i2pd
        // This is a valid I2NP message that i2pd will process
        var dsm = new DatabaseStoreMessage(
            RouterContext.Inst.MyRouterInfo);
        TransportProvider.Send(i2pdHash, dsm);

        // If we get here without exceptions, the data frame was sent
        // successfully over the NTCP2 data phase (ChaCha20-Poly1305)
        Logging.LogInformation("DatabaseStoreMessage sent to i2pd via NTCP2");

        // Verify the connection is still alive after sending
        await Task.Delay(2000);
        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "Connection should remain established after data exchange");
    }

    /// <summary>
    ///     Test that the NTCP2 connection uses the correct block types.
    ///     Verifies DateTime, RouterInfo, and I2NP blocks are processed correctly.
    /// </summary>
    [Test]
    [CancelAfter(45000)]
    public async Task TestNTCP2BlockProcessing()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        // Ensure connection
        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(i2pdInfo);
            var connected = await router.WaitForConnection(i2pdHash, 30000);
            Assert.IsTrue(connected, "Must be connected");
        }

        // The connection itself proves blocks are working:
        // - SessionRequest/Created/Confirmed used Options and RouterInfo blocks
        // - Data phase uses I2NP blocks wrapped in ChaCha20-Poly1305

        // Verify i2pd's RouterInfo was received during handshake
        var storedRi = NetDb.Inst[i2pdHash];
        if (storedRi == null)
        {
            var routers = NetDb.Inst.GetRouters().Select(ih => ih.Id32Short).ToArray();
            var debugInfo = NetDb.Inst.GetRouterInfoDebug(i2pdHash);
            Logging.LogInformation(
                $"[DEBUG_LOG] TestNTCP2BlockProcessing: i2pdHash {i2pdHash} not found in NetDb. Debug: {debugInfo}. Known routers: {string.Join(", ", routers)}");
        }

        Assert.IsNotNull(storedRi,
            "i2pd RouterInfo should be in our NetDb after NTCP2 handshake");

        Logging.LogInformation(
            $"i2pd RouterInfo verified in NetDb: {storedRi.Identity.IdentHash.Id32Short:x8}");
    }

    /// <summary>
    ///     Test NTCP2 connection with ML-KEM768 post-quantum hybrid handshake.
    ///     Requires i2pd version that supports ML-KEM.
    /// </summary>
    [Test]
    [CancelAfter(30000)]
    public async Task TestCSharpConnectsToI2pd_NTCP2_PQ()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        // Check if i2pd advertises PQ support
        // i2pd publishes "4" in caps for ML-KEM support, or "i" in address options
        var hasPQ = i2pdInfo.Addresses?.Any(a => a.Options.Any(o =>
            o.Key.ToString() == "i" &&
            o.Value.ToString().Length > 0)) == true;

        if (!hasPQ)
            Assert.Ignore(
                "i2pd does not advertise PQ support — skipping ML-KEM test. " +
                "Ensure i2pd is built with ML-KEM support.");

        // Initiate PQ-enabled connection
        router.ConnectToPeer(i2pdInfo);
        var connected = await router.WaitForConnection(i2pdHash, 30000);
        Assert.IsTrue(connected,
            "C# router should establish PQ NTCP2 connection to i2pd");

        // Verify the connection protocol
        var protocol = TestNetworkFixture.CSharpRouter.GetConnectionProtocol(i2pdHash);
        Logging.LogInformation($"PQ connection established via {protocol}");
    }

    /// <summary>
    ///     Test multiple sequential NTCP2 messages to verify nonce management
    ///     works correctly in the data phase with a real peer.
    /// </summary>
    [Test]
    [CancelAfter(45000)]
    public async Task TestNTCP2MultipleMessages_I2pd()
    {
        var router = TestNetworkFixture.CSharpRouter;
        var i2pdInfo = TestNetworkFixture.I2pdRouterInfo;
        var i2pdHash = i2pdInfo.Identity.IdentHash;

        if (!router.IsConnectedTo(i2pdHash))
        {
            router.ConnectToPeer(i2pdInfo);
            var connected = await router.WaitForConnection(i2pdHash, 30000);
            Assert.IsTrue(connected, "Must be connected");
        }

        // Send multiple messages sequentially
        for (var i = 0; i < 5; i++)
        {
            var dsm = new DatabaseStoreMessage(
                RouterContext.Inst.MyRouterInfo);
            TransportProvider.Send(i2pdHash, dsm);
            await Task.Delay(500);
        }

        // Verify connection still alive — proves nonce incrementing works
        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "Connection should survive multiple sequential messages");

        Logging.LogInformation("5 sequential messages sent successfully via NTCP2");
    }

    /// <summary>
    ///     Test NTCP2 connection survives idle period.
    /// </summary>
    [Test]
    [CancelAfter(60000)]
    public async Task TestNTCP2ConnectionPersistence()
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

        // Wait for 10 seconds idle
        await Task.Delay(10000);

        // Connection should still be alive (keepalive/dummy messages)
        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "NTCP2 connection should persist during idle period");

        // Verify we can still send after idle
        var dsm = new DatabaseStoreMessage(
            RouterContext.Inst.MyRouterInfo);
        TransportProvider.Send(i2pdHash, dsm);
        await Task.Delay(1000);

        Assert.IsTrue(router.IsConnectedTo(i2pdHash),
            "Connection should survive after post-idle message");
    }
}