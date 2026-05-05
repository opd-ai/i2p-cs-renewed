using System.Buffers;
using System.Net;
using I2PCore;
using I2PCore.Client;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TunnelLayer;
using I2PCore.Utils;

namespace I2PRouterCli;

internal class Program
{
    private static bool _isRunning;

    private static void Main(string[] args)
    {
        // Configure logging - no web interface, just console and file
        Logging.ReadAppConfig();
        Logging.SetLogLevel(Logging.LogLevels.Information);
        Logging.LogToDebug = false;
        Logging.LogToConsole = true;

        // Clear existing log file on startup for clean logs
        var logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "logs.txt");
        if (File.Exists(logFilePath)) File.Delete(logFilePath);
        Logging.LogToFile(logFilePath);
        Logging.LogInformation($"Logging to file: {logFilePath}");

        // Default settings
        IPAddress? externalAddress = null;
        var tcpPort = 12345;
        var udpPort = 12345;
        var isFirewalled = true;
        var useIPv6 = false;
        var disableIPv6 = false; // inverse of useIPv6 for CLI flag
        var enableSSU2 = false;
        var floodfill = false;
        var testEepsite = false;
        var httpProxyPort = 4445; // Default to 4445 (4444 might be in use)

        var hiddenMode = false;
        string? dataDir = null;
        var netId = 0; // 0 = use default (2)
        var disableReseed = false;
        var samPort = 0; // 0 = use default
        var exploratoryLength = 2;
        var exploratoryQuantity = 3;

        // Parse command line arguments
        for (var i = 0; i < args.Length; ++i)
            switch (args[i])
            {
                case "--hidden":
                    hiddenMode = true;
                    Console.WriteLine("Hidden mode enabled");
                    break;

                case "--test-example-eepsite":
                    testEepsite = true;
                    Console.WriteLine("Will test example eepsite after router is ready");
                    break;

                case "--http-proxy-port":
                    if (args.Length > i + 1)
                    {
                        httpProxyPort = int.Parse(args[++i]);
                        Console.WriteLine($"HTTP proxy port set to {httpProxyPort}");
                    }

                    break;

                case "--proxy-encryption":
                    if (args.Length > i + 1)
                    {
                        var mode = args[++i].ToLowerInvariant();
                        switch (mode)
                        {
                            case "ecies":
                                RouterContext.Inst.ProxyEncryption = RouterContext.HttpProxyEncryptionType.Ecies;
                                break;
                            case "mlkem":
                                RouterContext.Inst.ProxyEncryption = RouterContext.HttpProxyEncryptionType.Mlkem;
                                break;
                            case "hybrid":
                                RouterContext.Inst.ProxyEncryption = RouterContext.HttpProxyEncryptionType.Hybrid;
                                break;
                            default:
                                Console.WriteLine($"Unknown proxy encryption mode: {mode}. Using hybrid.");
                                break;
                        }

                        Console.WriteLine($"Proxy encryption: {RouterContext.Inst.ProxyEncryption}");
                    }

                    break;

                case "--external-ip":
                    if (args.Length > i + 1)
                    {
                        externalAddress = IPAddress.Parse(args[++i]);
                        Console.WriteLine($"External IP set to {externalAddress}");
                    }
                    else
                    {
                        Console.WriteLine("--external-ip requires an IP address");
                        return;
                    }

                    break;

                case "--ntcp2-port":
                    if (args.Length > i + 1)
                    {
                        tcpPort = int.Parse(args[++i]);
                        udpPort = tcpPort; // keep them synchronized by default
                        Console.WriteLine($"NTCP2 port set to {tcpPort}");
                    }
                    else
                    {
                        Console.WriteLine("--ntcp2-port requires a port number");
                        return;
                    }

                    break;

                case "--ssu2-port":
                    if (args.Length > i + 1)
                    {
                        udpPort = int.Parse(args[++i]);
                        enableSSU2 = true; // Auto-enable SSU2 if port is specified
                        Console.WriteLine($"SSU2 port set to {udpPort}");
                    }
                    else
                    {
                        Console.WriteLine("--ssu2-port requires a port number");
                        return;
                    }

                    break;

                case "--enable-ssu2":
                    enableSSU2 = true;
                    Console.WriteLine("SSU2: enabled");
                    break;

                case "--is-firewalled":
                    isFirewalled = true;
                    Console.WriteLine($"Firewalled mode: {isFirewalled}");
                    break;

                case "--not-firewalled":
                    isFirewalled = false;
                    Console.WriteLine($"Firewalled mode: {isFirewalled}");
                    break;

                case "--disable-ipv6":
                    disableIPv6 = true;
                    useIPv6 = false;
                    Console.WriteLine("IPv6 disabled");
                    break;

                case "--enable-ipv6":
                    disableIPv6 = false;
                    useIPv6 = true;
                    Console.WriteLine("IPv6 enabled");
                    break;

                case "--disable-ssu2":
                    enableSSU2 = false;
                    Console.WriteLine("SSU2 disabled");
                    break;

                case "--floodfill":
                    floodfill = true;
                    Console.WriteLine("Floodfill mode: enabled");
                    break;

                case "--data-dir":
                    if (args.Length > i + 1)
                    {
                        dataDir = args[++i];
                        Console.WriteLine($"Data directory set to {dataDir}");
                    }

                    break;

                case "--netid":
                    if (args.Length > i + 1)
                    {
                        netId = int.Parse(args[++i]);
                        Console.WriteLine($"Network ID set to {netId}");
                    }

                    break;

                case "--disable-reseed":
                    disableReseed = true;
                    Console.WriteLine("Reseed disabled");
                    break;

                case "--sam-port":
                    if (args.Length > i + 1)
                    {
                        samPort = int.Parse(args[++i]);
                        Console.WriteLine($"SAM port set to {samPort}");
                    }

                    break;

                case "--exploratory-length":
                    if (args.Length > i + 1)
                    {
                        exploratoryLength = int.Parse(args[++i]);
                        Console.WriteLine($"Exploratory length set to {exploratoryLength}");
                    }

                    break;

                case "--exploratory-quantity":
                    if (args.Length > i + 1)
                    {
                        exploratoryQuantity = int.Parse(args[++i]);
                        Console.WriteLine($"Exploratory quantity set to {exploratoryQuantity}");
                    }

                    break;

                case "--help":
                case "-h":
                    PrintHelp();
                    return;

                default:
                    Console.WriteLine($"Unknown argument: {args[i]}");
                    PrintHelp();
                    return;
            }

        // Apply pre-init settings (must be set BEFORE RouterContext.Inst is accessed)
        if (!string.IsNullOrEmpty(dataDir))
        {
            Directory.CreateDirectory(dataDir);
            StreamUtils.AppPathOverride = dataDir;
        }

        if (netId > 0) I2PConstants.I2PNetworkId = netId;

        if (disableReseed) Bootstrap.Disabled = true;

        // Apply configuration to router context
        RouterContext.RouterSettingsFile = "I2PRouterCli.bin";

        if (externalAddress != null) RouterContext.Inst.DefaultExtAddress = externalAddress;

        RouterContext.Inst.DefaultTcpPort = tcpPort;
        RouterContext.Inst.DefaultUdpPort = udpPort;
        RouterContext.Inst.IsFirewalled = isFirewalled;
        RouterContext.UseIpV6 = useIPv6 && !disableIPv6;
        RouterContext.Inst.EnableSSU2 = enableSSU2;
        RouterContext.Inst.FloodfillEnabled = floodfill;

        TunnelPoolSettings.DEFAULT_IB_EXPL_LENGTH = exploratoryLength;
        TunnelPoolSettings.DEFAULT_OB_EXPL_LENGTH = exploratoryLength;
        TunnelPoolSettings.DEFAULT_QUANTITY = exploratoryQuantity;

        // Auto-enable hidden mode when firewalled (matches Java I2P behavior)
        if (isFirewalled || hiddenMode)
        {
            RouterContext.Inst.IsHidden = true;
            Console.WriteLine("Hidden mode: enabled (firewalled router)");
        }

        // Apply the new settings
        RouterContext.Inst.ApplyNewSettings();

        // Start the router
        Router.Start();

        _isRunning = true;
        Logging.LogInformation("I2P Router CLI started");

        Console.WriteLine("I2P Router CLI is running. Press Ctrl+C to stop.");
        Console.WriteLine("Router ID: {0:x8}", RouterContext.Inst.MyRouterIdentity.IdentHash.Id32Short);
        Console.WriteLine($"Listening on TCP:{tcpPort}, UDP:{udpPort}");
        Console.WriteLine(
            $"Firewalled: {isFirewalled}, IPv6: {useIPv6 && !disableIPv6}, SSU2: {enableSSU2}, Floodfill: {floodfill}");

        // Export RouterInfo as router.info for integration test peer discovery
        try
        {
            var ri = RouterContext.Inst.MyRouterInfo;
            var brs = new ArrayBufferWriter<byte>();
            ri.Write(brs);
            var riPath = Path.Combine(
                dataDir ?? Directory.GetCurrentDirectory(), "router.info");
            File.WriteAllBytes(riPath, brs.WrittenSpan.ToArray());
            Logging.LogInformation($"RouterInfo exported to {riPath}");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to export RouterInfo: {ex.Message}");
        }

        // Start HTTP proxy
        try
        {
            ClientContext.Inst.SetConfig(
                ClientContext.CfgHttpProxyPort, httpProxyPort.ToString());
            ClientContext.Inst.SetConfig(
                ClientContext.CfgHttpProxyEnabled, "true");
            // Configure SAM bridge
            if (samPort > 0)
            {
                ClientContext.Inst.SetConfig(
                    ClientContext.CfgSamEnabled, "true");
                ClientContext.Inst.SetConfig(
                    ClientContext.CfgSamPort, samPort.ToString());
                Console.WriteLine($"SAM bridge enabled on port {samPort}");
            }
            else
            {
                ClientContext.Inst.SetConfig(
                    ClientContext.CfgSamEnabled, "false");
            }

            // Disable SOCKS to avoid port conflicts
            ClientContext.Inst.SetConfig(
                ClientContext.CfgSocksProxyEnabled, "false");
            ClientContext.Inst.Start();
            Console.WriteLine($"HTTP proxy started on 127.0.0.1:{httpProxyPort}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to start HTTP proxy: {ex.Message}");
            Logging.Log(ex);
        }

        // Start eepsite test in background if requested
        if (testEepsite)
        {
            var proxyPort = httpProxyPort;
            Task.Run(async () => { await TestEepsite(proxyPort); });
        }

        // Keep the application running until interrupted
        try
        {
            while (_isRunning) Thread.Sleep(1000);
        }
        catch (ThreadInterruptedException)
        {
            // Handle graceful shutdown
        }
        catch (Exception ex)
        {
            Logging.Log(ex);
        }
        finally
        {
            StopRouter();
        }
    }

    private static void StopRouter()
    {
        if (_isRunning)
        {
            Router.Stop();
            _isRunning = false;
            Logging.LogInformation("I2P Router CLI stopped");
            Console.WriteLine("I2P Router CLI stopped.");
        }
    }

    private static async Task TestEepsite(int proxyPort)
    {
        const string testUrl = "http://nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p/";
        const int minRouters = 100;
        const int maxWaitMinutes = 10;

        Logging.LogInformation("TestEepsite: Waiting for router to be ready...");

        // Wait for enough routers and established tunnels
        var startTime = DateTime.UtcNow;
        while (_isRunning)
        {
            var elapsed = DateTime.UtcNow - startTime;
            if (elapsed.TotalMinutes > maxWaitMinutes)
            {
                Logging.LogWarning($"TestEepsite: Timeout after {maxWaitMinutes} minutes. " +
                                   $"Router count: {NetDb.Inst.RouterCount}");
                break;
            }

            var routerCount = NetDb.Inst.RouterCount;
            var hasOutbound = TunnelProvider.Inst.OutboundTunnelCount > 0;
            var hasInbound = TunnelProvider.Inst.InboundTunnelCount > 0;

            // Need at least 2 outbound and 2 inbound tunnels for reliable operation
            var outCount = TunnelProvider.Inst.OutboundTunnelCount;
            var inCount = TunnelProvider.Inst.InboundTunnelCount;

            if (routerCount >= minRouters && outCount >= 2 && inCount >= 2)
            {
                Logging.LogInformation($"TestEepsite: Router ready. {routerCount} routers, " +
                                       $"tunnels out={outCount}, in={inCount}.");
                break;
            }

            Logging.LogInformation($"TestEepsite: Waiting... {routerCount} routers, " +
                                   $"out={outCount}, in={inCount}");
            await Task.Delay(15000);
        }

        if (!_isRunning) return;

        // Wait for tunnel pool and client destination tunnels to stabilize.
        // Client inbound tunnels can take 60-120 seconds to build.
        Logging.LogInformation("TestEepsite: Waiting 90s for tunnel pool to stabilize...");
        await Task.Delay(90000);

        Logging.LogInformation($"TestEepsite: Fetching {testUrl} via HTTP proxy...");

        try
        {
            var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"),
                UseProxy = true
            };

            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromMinutes(3);

            var response = await client.GetAsync(testUrl);
            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("=== EEPSITE TEST RESULT ===");
            Console.WriteLine($"Status: {response.StatusCode}");
            Console.WriteLine($"Content length: {content.Length}");
            if (content.Length > 2000)
                Console.WriteLine(content.Substring(0, 2000) + "...");
            else
                Console.WriteLine(content);
            Console.WriteLine("=== END EEPSITE TEST ===");

            Logging.LogInformation($"TestEepsite: SUCCESS! Status={response.StatusCode}, " +
                                   $"Length={content.Length}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("=== EEPSITE TEST FAILED ===");
            Console.WriteLine($"Error: {ex.Message}");
            if (ex.InnerException != null)
                Console.WriteLine($"Inner: {ex.InnerException.Message}");
            Console.WriteLine("=== END EEPSITE TEST ===");

            Logging.LogWarning($"TestEepsite: FAILED: {ex.Message}");
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("I2PRouterCli - CLI-only I2P Router");
        Console.WriteLine("");
        Console.WriteLine("Usage:");
        Console.WriteLine("  I2PRouterCli [options]");
        Console.WriteLine("");
        Console.WriteLine("Options:");
        Console.WriteLine("  --external-ip <IP>      Set external IP address");
        Console.WriteLine("  --ntcp2-port <PORT>     Set NTCP2 port (default: 12345)");
        Console.WriteLine("  --ssu2-port <PORT>      Set SSU2 port (default: 12345)");
        Console.WriteLine("  --is-firewalled         Run in firewalled mode (default)");
        Console.WriteLine("  --not-firewalled        Run in non-firewalled mode");
        Console.WriteLine("  --disable-ipv6          Disable IPv6 support");
        Console.WriteLine("  --enable-ipv6           Enable IPv6 support");
        Console.WriteLine("  --disable-ssu2          Disable SSU2 transport");
        Console.WriteLine("  --floodfill             Enable floodfill mode");
        Console.WriteLine("  --proxy-encryption <mode> Set HTTP proxy encryption (ecies, mlkem, hybrid)");
        Console.WriteLine("  --data-dir <path>       Set custom data directory");
        Console.WriteLine("  --netid <N>             Set network ID (default: 2)");
        Console.WriteLine("  --disable-reseed        Disable network bootstrap/reseed");
        Console.WriteLine("  --sam-port <PORT>       Enable SAM bridge on specified port");
        Console.WriteLine("  --help, -h              Show this help message");
        Console.WriteLine("");
        Console.WriteLine("Examples:");
        Console.WriteLine("  I2PRouterCli --external-ip 1.2.3.4 --ntcp2-port 9090 --ssu2-port 9091");
        Console.WriteLine("  I2PRouterCli --not-firewalled --disable-ipv6");
    }
}