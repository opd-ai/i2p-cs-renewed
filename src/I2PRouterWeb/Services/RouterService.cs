using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using I2PCore;
using I2PCore.Client;
using I2PCore.Data;
using I2PCore.SessionLayer;
using I2PCore.TransportLayer;
using I2PCore.TransportLayer.Log;
using I2PCore.TunnelLayer;
using I2PCore.Utils;
using I2PRouterWeb.Pages;

namespace I2PRouterWeb.Services;

public class RouterService
{
    private const int MaxActivityLogEntries = 1000;
    private const string SettingsFilename = "web_settings.json";
    private readonly ConcurrentQueue<ActivityLogEntry> _activityLog = new();
    private readonly NetDbLogService _netDbLogService;
    private DateTime? _startTime;

    public RouterService(NetDbLogService netDbLogService)
    {
        _netDbLogService = netDbLogService;
        LoadSettings();
    }

    public IPAddress? ExternalAddress { get; set; }
    public int TcpPort { get; set; } = 12345;
    public int UdpPort { get; set; } = 12345;
    public bool IsFirewalled { get; set; } = true;
    public bool UseIPv6 { get; set; }
    public bool EnableSSU2 { get; set; } = true;
    public bool FloodfillEnabled { get; set; }
    public int MaxTransitTunnels { get; set; } = 10000;
    public int MaxNtcp2InboundConnections { get; set; } = 2500;
    public int MaxNtcp2OutboundConnections { get; set; } = 2500;
    public int TransitSharePercent { get; set; } = 80;

    public RouterContext.HttpProxyEncryptionType ProxyEncryption { get; set; } =
        RouterContext.HttpProxyEncryptionType.Hybrid;

    public int HttpProxyPort { get; set; } = 4445;

    public bool IsRunning { get; private set; }

    public bool IsHttpProxyRunning => ClientContext.Inst?.HTTPProxy?.IsRunning ?? false;

    /// <summary>
    ///     Get the detected external IPv4 address (from peer reports or manual config)
    /// </summary>
    public IPAddress? DetectedExternalAddress => RouterContext.Inst?.ExtIpv4Address;

    public async Task ReseedAsync()
    {
        LogActivity("Network", "Triggering manual reseed from servers...");
        await Bootstrap.NetworkBootstrap();
    }

    public async Task<int> ReseedFromFileAsync(byte[] data)
    {
        LogActivity("Network", $"Manual reseed from uploaded file ({data.Length} bytes)...");
        var count = Bootstrap.ImportReseedFile(new I2PByteBlock(data));
        LogActivity("Network", $"Manual reseed imported {count} routers.");
        return count;
    }

    public IEnumerable<HttpProxyLogger.LogEntry> GetHttpProxyLogs()
    {
        return HttpProxyLogger.Inst.GetLogs().Reverse();
    }

    public IEnumerable<ServerTunnelLogger.LogEntry> GetServerTunnelLogs()
    {
        return ServerTunnelLogger.Inst.GetLogs().Reverse();
    }

    public IEnumerable<ActivityLogEntry> GetActivityLog()
    {
        return _activityLog.ToArray().Reverse();
    }

    public IEnumerable<TransportConnectionLogger.LogEntry> GetTransportConnectionLogs()
    {
        return TransportConnectionLogger.Inst.GetEntries();
    }

    public TransportConnectionLogger.ConnectionStats GetConnectionStats()
    {
        return TransportConnectionLogger.Inst.GetConnectionStats();
    }

    public IEnumerable<(string Reason, int Count, IEnumerable<(string ShortId, string FullId)> Routers)>
        GetTopFailureReasons(string transport, string direction, int topN = 30)
    {
        return TransportConnectionLogger.Inst.GetTopFailureReasons(transport, direction, topN);
    }

    public IEnumerable<(string ShortId, string FullId, int Count, IEnumerable<(string Reason, int Count)> Reasons)>
        GetTopFailedRouters(string transport, string direction, int topN = 30)
    {
        return TransportConnectionLogger.Inst.GetTopFailedRouters(transport, direction, topN);
    }

    public IEnumerable<TransportConnectionLogger.DetailedFailureInfo> GetFailuresByReason(
        string transport, string direction, string reason)
    {
        return TransportConnectionLogger.Inst.GetDetailedFailuresByReason(transport, direction, reason);
    }

    public IEnumerable<(string B32Address, int Count)> GetTopLeaseSetLookups(int topN = 100)
    {
        var ff = Router.FloodfillServer;
        if (ff == null) return Enumerable.Empty<(string, int)>();
        return ff.GetTopLeaseSetLookups(topN)
            .Select(x => (B32Address: x.Key.Id32 + ".b32.i2p", Count: x.Count));
    }

    public IEnumerable<(string RouterHash, string ShortId, int Count)> GetTopRouterInfoLookups(int topN = 100)
    {
        var ff = Router.FloodfillServer;
        if (ff == null) return Enumerable.Empty<(string, string, int)>();
        return ff.GetTopRouterInfoLookups(topN)
            .Select(x => (RouterHash: x.Key.Id64, ShortId: x.Key.Id64, Count: x.Count));
    }

    public void StartRouter()
    {
        if (IsRunning)
        {
            LogActivity("Router", "Router already running");
            return;
        }

        RouterContext.RouterSettingsFile = "I2PRouterWeb.bin";

        if (ExternalAddress != null) RouterContext.Inst.DefaultExtAddress = ExternalAddress;

        RouterContext.Inst.DefaultTcpPort = TcpPort;
        RouterContext.Inst.DefaultUdpPort = UdpPort;
        RouterContext.Inst.IsFirewalled = IsFirewalled;
        RouterContext.UseIpV6 = UseIPv6;
        RouterContext.Inst.EnableSSU2 = EnableSSU2;
        RouterContext.Inst.FloodfillEnabled = FloodfillEnabled;
        RouterContext.Inst.MaxTransitTunnels = MaxTransitTunnels;
        RouterContext.Inst.MaxNtcp2InboundConnections = MaxNtcp2InboundConnections;
        RouterContext.Inst.MaxNtcp2OutboundConnections = MaxNtcp2OutboundConnections;
        RouterContext.Inst.TransitSharePercent = TransitSharePercent;
        RouterContext.Inst.ProxyEncryption = ProxyEncryption;

        RouterContext.Inst.ApplyNewSettings();

        Router.Start();
        _netDbLogService.Initialize();

        IsRunning = true;
        _startTime = DateTime.UtcNow;

        LogActivity("Router", "I2P Router started");
        Logging.LogInformation("I2P Router started");
    }

    public void StopRouter()
    {
        if (!IsRunning)
        {
            LogActivity("Router", "Router not running");
            return;
        }

        Router.Stop();

        IsRunning = false;
        _startTime = null;

        LogActivity("Router", "I2P Router stopped");
        Logging.LogInformation("I2P Router stopped");
    }

    public void StartHttpProxy()
    {
        if (!IsRunning)
        {
            LogActivity("HTTP Proxy", "Cannot start HTTP proxy - router not running");
            return;
        }

        if (IsHttpProxyRunning)
        {
            LogActivity("HTTP Proxy", "HTTP proxy already running");
            return;
        }

        var ctx = ClientContext.Inst;
        ctx.SetConfig(ClientContext.CfgHttpProxyPort, HttpProxyPort.ToString());
        ctx.SetConfig(ClientContext.CfgHttpProxyEnabled, "true");
        ctx.StartHTTPProxy();

        LogActivity("HTTP Proxy", $"HTTP proxy started on 127.0.0.1:{HttpProxyPort}");

        if (ctx.HTTPProxy?.ClientDestination?.Destination != null)
        {
            var dest = ctx.HTTPProxy.ClientDestination.Destination;
            var b64 = FreenetBase64.Encode(new I2PByteBlock(dest.ToByteArray()));
            var b32 = dest.IdentHash.Id32 + ".b32.i2p";

            LogActivity("HTTP Proxy", $"Destination (b32): {b32}");
            LogActivity("HTTP Proxy", $"Destination (b64): {b64}");
        }

        Logging.LogInformation($"HTTP proxy started on 127.0.0.1:{HttpProxyPort}");
    }

    public void StopHttpProxy()
    {
        if (!IsHttpProxyRunning)
        {
            LogActivity("HTTP Proxy", "HTTP proxy not running");
            return;
        }

        ClientContext.Inst?.StopHTTPProxy();

        LogActivity("HTTP Proxy", "HTTP proxy stopped");
        Logging.LogInformation("HTTP proxy stopped");
    }

    public void ApplySettings(IPAddress? externalAddress, int tcpPort, int udpPort, bool isFirewalled, bool useIPv6,
        bool enableSSU2, bool floodfillEnabled, RouterContext.HttpProxyEncryptionType proxyEncryption,
        int? maxTransitTunnels = null, int? transitSharePercent = null, int? maxNtcp2Inbound = null,
        int? maxNtcp2Outbound = null)
    {
        ExternalAddress = externalAddress;
        TcpPort = tcpPort;
        UdpPort = udpPort;
        IsFirewalled = isFirewalled;
        UseIPv6 = useIPv6;
        EnableSSU2 = enableSSU2;
        FloodfillEnabled = floodfillEnabled;
        ProxyEncryption = proxyEncryption;
        if (maxTransitTunnels.HasValue) MaxTransitTunnels = maxTransitTunnels.Value;
        if (transitSharePercent.HasValue) TransitSharePercent = transitSharePercent.Value;
        if (maxNtcp2Inbound.HasValue) MaxNtcp2InboundConnections = maxNtcp2Inbound.Value;
        if (maxNtcp2Outbound.HasValue) MaxNtcp2OutboundConnections = maxNtcp2Outbound.Value;

        var proxyEncryptionChanged = RouterContext.Inst.ProxyEncryption != ProxyEncryption;
        var proxyRunning = IsHttpProxyRunning;

        if (proxyEncryptionChanged && proxyRunning) StopHttpProxy();

        if (ExternalAddress != null) RouterContext.Inst.DefaultExtAddress = ExternalAddress;

        RouterContext.Inst.DefaultTcpPort = TcpPort;
        RouterContext.Inst.DefaultUdpPort = UdpPort;
        RouterContext.Inst.IsFirewalled = IsFirewalled;
        RouterContext.UseIpV6 = UseIPv6;
        RouterContext.Inst.EnableSSU2 = EnableSSU2;
        RouterContext.Inst.FloodfillEnabled = FloodfillEnabled;
        RouterContext.Inst.MaxTransitTunnels = MaxTransitTunnels;
        RouterContext.Inst.MaxNtcp2InboundConnections = MaxNtcp2InboundConnections;
        RouterContext.Inst.MaxNtcp2OutboundConnections = MaxNtcp2OutboundConnections;
        RouterContext.Inst.TransitSharePercent = TransitSharePercent;
        RouterContext.Inst.ProxyEncryption = ProxyEncryption;

        RouterContext.Inst.ApplyNewSettings();

        if (proxyEncryptionChanged && proxyRunning) StartHttpProxy();

        LogActivity("Settings",
            $"Applied new settings: Port {TcpPort}, Firewalled: {IsFirewalled}, SSU2: {EnableSSU2}, Floodfill: {FloodfillEnabled}, Encryption: {ProxyEncryption}, Max Transit Tunnels: {MaxTransitTunnels}, NTCP2 In/Out: {MaxNtcp2InboundConnections}/{MaxNtcp2OutboundConnections}");

        SaveSettings();
    }

    public void LogActivity(string category, string message)
    {
        _activityLog.Enqueue(new ActivityLogEntry
        {
            Timestamp = DateTime.UtcNow,
            Category = category,
            Message = message
        });

        while (_activityLog.Count > MaxActivityLogEntries) _activityLog.TryDequeue(out _);
    }

    public RouterStatistics GetStatistics()
    {
        var uptime = _startTime.HasValue ? DateTime.UtcNow - _startTime.Value : TimeSpan.Zero;

        var stats = new RouterStatistics
        {
            RouterHash = RouterContext.Inst.MyRouterIdentity.IdentHash.Id64,
            Version = I2PConstants.ProtocolVersion,
            Uptime = uptime,
            PublicKey = FreenetBase64.Encode(new I2PByteBlock(RouterContext.Inst.MyRouterIdentity.PublicKey.ToByteArray())),
            KeyType = RouterContext.Inst.MyRouterIdentity.PublicKey.Certificate.PublicKeyType.ToString(),
            IsRunning = IsRunning,
            BandwidthClass = RouterContext.Inst.GetBandwidthCapChar().ToString(),
            FullRouterInfo = IsRunning ? RouterContext.Inst.MyRouterInfo : null
        };

        // NetDb and Transport stats
        try
        {
            stats.KnownRouters = NetDb.Inst?.RouterCount ?? 0;
            stats.KnownFloodfills = NetDb.Inst?.FloodfillCount ?? 0;
            stats.NTCP2SessionCount = TransportProvider.Inst?.Ntcp2SessionCount ?? 0;
            stats.SSU2SessionCount = TransportProvider.Inst?.Ssu2SessionCount ?? 0;

            stats.InboundTunnels = TunnelProvider.Inst?.InboundTunnelCount ?? 0;
            stats.OutboundTunnels = TunnelProvider.Inst?.OutboundTunnelCount ?? 0;
            stats.ExploratoryTunnels = (TunnelProvider.Inst?.GetInboundTunnels()
                                           ?.Count(t => t.Config?.Pool == TunnelConfig.TunnelPool.Exploratory) ?? 0) +
                                       (TunnelProvider.Inst?.GetOutboundTunnels()?.Count(t =>
                                           t.Config?.Pool == TunnelConfig.TunnelPool.Exploratory) ?? 0);
            stats.TransitTunnels = Router.TransitTunnelMgr?.TransitTunnelCount ?? 0;

            stats.HTTPProxyRunning = IsHttpProxyRunning;
            stats.HTTPProxyPort = HttpProxyPort;
        }
        catch
        {
        }

        return stats;
    }

    public IEnumerable<TransitTunnelInfo> GetTransitTunnels()
    {
        var result = new List<TransitTunnelInfo>();
        if (Router.TransitTunnelMgr == null) return result;

        foreach (var tunnel in Router.TransitTunnelMgr.GetTunnels())
        {
            var isInboundGateway = tunnel is GatewayTunnel;
            var isOutboundEndpoint = tunnel is EndpointTunnel;
            var destHash = tunnel.Destination;

            // Extract ReceiveFrom (previous hop) from the specific tunnel type
            I2PIdentHash? receiveFrom = null;
            if (tunnel is TransitTunnel tt) receiveFrom = tt.ReceiveFrom;
            else if (tunnel is EndpointTunnel et) receiveFrom = et.ReceiveFrom;
            else if (tunnel is GatewayTunnel gt) receiveFrom = gt.ReceiveFrom;

            string fromLabel;
            string? fromHash = null;
            if (isInboundGateway)
            {
                fromLabel = "Any peer (Inbound Gateway)";
            }
            else if (receiveFrom != null)
            {
                fromLabel = receiveFrom.Id64Short;
                fromHash = receiveFrom.Id64;
            }
            else
            {
                fromLabel = "Unknown";
            }

            string toLabel;
            string? toHash = null;
            if (isOutboundEndpoint)
            {
                toLabel = destHash?.Id64Short ?? "Outbound Endpoint";
                toHash = destHash?.Id64;
            }
            else
            {
                toLabel = destHash?.Id64Short ?? "Unknown";
                toHash = destHash?.Id64;
            }

            result.Add(new TransitTunnelInfo
            {
                TunnelId = tunnel.ReceiveTunnelId.ToString(),
                FromRouter = fromLabel,
                FromRouterHash = fromHash,
                ToRouter = toLabel,
                ToRouterHash = toHash,
                IsOutboundEndpoint = isOutboundEndpoint,
                IsInboundGateway = isInboundGateway,
                MessageCount = tunnel.MessageCount,
                BytesSent = tunnel.Bandwidth.SendBandwidth.DataBytes,
                BytesReceived = tunnel.Bandwidth.ReceiveBandwidth.DataBytes,
                SendBitrateKBps = tunnel.Bandwidth.SendBandwidth.Bitrate / 8192f,
                ReceiveBitrateKBps = tunnel.Bandwidth.ReceiveBandwidth.Bitrate / 8192f,
                LastActivity = DateTime.UtcNow -
                               TimeSpan.FromMilliseconds(tunnel.EstablishedTime.DeltaToNowMilliseconds)
            });
        }

        return result;
    }

    private string SettingsFilePath => Path.Combine(Directory.GetCurrentDirectory(), SettingsFilename);

    private void LoadSettings()
    {
        try
        {
            var path = SettingsFilePath;
            if (!File.Exists(path)) return;

            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<WebRouterSettings>(json);
            if (settings == null) return;

            if (settings.ExternalAddress != null)
                ExternalAddress = IPAddress.TryParse(settings.ExternalAddress, out var addr) ? addr : null;

            TcpPort = settings.TcpPort;
            UdpPort = settings.UdpPort;
            IsFirewalled = settings.IsFirewalled;
            UseIPv6 = settings.UseIPv6;
            EnableSSU2 = settings.EnableSSU2;
            FloodfillEnabled = settings.FloodfillEnabled;
            MaxTransitTunnels = settings.MaxTransitTunnels;
            MaxNtcp2InboundConnections = settings.MaxNtcp2InboundConnections;
            MaxNtcp2OutboundConnections = settings.MaxNtcp2OutboundConnections;
            TransitSharePercent = settings.TransitSharePercent;
            ProxyEncryption = settings.ProxyEncryption;
            HttpProxyPort = settings.HttpProxyPort;

            LogActivity("Settings", "Loaded settings from disk.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to load settings: {ex.Message}");
        }
    }

    private void SaveSettings()
    {
        try
        {
            var settings = new WebRouterSettings
            {
                ExternalAddress = ExternalAddress?.ToString(),
                TcpPort = TcpPort,
                UdpPort = UdpPort,
                IsFirewalled = IsFirewalled,
                UseIPv6 = UseIPv6,
                EnableSSU2 = EnableSSU2,
                FloodfillEnabled = FloodfillEnabled,
                MaxTransitTunnels = MaxTransitTunnels,
                MaxNtcp2InboundConnections = MaxNtcp2InboundConnections,
                MaxNtcp2OutboundConnections = MaxNtcp2OutboundConnections,
                TransitSharePercent = TransitSharePercent,
                ProxyEncryption = ProxyEncryption,
                HttpProxyPort = HttpProxyPort
            };

            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsFilePath, json);

            LogActivity("Settings", "Saved settings to disk.");
        }
        catch (Exception ex)
        {
            Logging.LogWarning($"Failed to save settings: {ex.Message}");
        }
    }

    public IEnumerable<KeyValuePair<string, Dictionary<string, string>>> GetTunnelsConfig()
    {
        var path = ClientContext.GetTunnelsConfigPath();
        if (!File.Exists(path)) return Enumerable.Empty<KeyValuePair<string, Dictionary<string, string>>>();

        var config = new I2PConfig();
        config.ParseTunnelsConfig(path);

        var result = new List<KeyValuePair<string, Dictionary<string, string>>>();
        foreach (var section in config.GetSections()) result.Add(new KeyValuePair<string, Dictionary<string, string>>(section, config.GetSection(section)));

        return result;
    }

    public void SaveTunnelConfig(string name, Dictionary<string, string> options)
    {
        var path = ClientContext.GetTunnelsConfigPath();
        var config = new I2PConfig();
        if (File.Exists(path)) config.ParseTunnelsConfig(path);

        foreach (var opt in options) config.SetSectionOption(name, opt.Key, opt.Value);

        config.SaveConfigFile(path);
        LogActivity("Tunnels", $"Saved configuration for tunnel '{name}'.");
    }

    public void RemoveTunnelConfig(string name)
    {
        var path = ClientContext.GetTunnelsConfigPath();
        var config = new I2PConfig();
        if (File.Exists(path)) config.ParseTunnelsConfig(path);

        config.RemoveSection(name);
        config.SaveConfigFile(path);
        LogActivity("Tunnels", $"Removed configuration for tunnel '{name}'.");
    }

    public bool IsTunnelRunning(string name)
    {
        return ClientContext.Inst?.GetTunnel(name) != null;
    }

    public string? GetTunnelB32Address(string name)
    {
        // Try to get from running tunnel
        var activeTunnel = ClientContext.Inst?.GetTunnel(name);
        if (activeTunnel?.MyDestination != null)
        {
            return activeTunnel.MyDestination.Destination.IdentHash.Id32;
        }

        // Fallback: Read from config and keys file
        var configs = GetTunnelsConfig().ToDictionary(k => k.Key, v => v.Value);
        if (configs.TryGetValue(name, out var config))
        {
            var keysFile = config.GetValueOrDefault("keys", "");
            if (!string.IsNullOrEmpty(keysFile))
            {
                var path = Path.IsPathRooted(keysFile) ? keysFile : Path.Combine(RouterContext.RouterPath, keysFile);
                if (File.Exists(path))
                {
                    try
                    {
                        var destInfo = new I2PDestinationInfo(File.ReadAllText(path));
                        return destInfo.Destination.IdentHash.Id32;
                    }
                    catch { }
                }
            }
        }
        return null;
    }

    public void StartTunnel(string name)
    {
        var configs = GetTunnelsConfig().ToDictionary(k => k.Key, v => v.Value);
        if (configs.TryGetValue(name, out var config))
        {
            ClientContext.Inst?.StartGenericTunnel(name, config);
            LogActivity("Tunnels", $"Started tunnel '{name}'.");
        }
    }

    public void ToggleTunnelAutostart(string name)
    {
        var configs = GetTunnelsConfig().ToDictionary(k => k.Key, v => v.Value);
        if (configs.TryGetValue(name, out var config))
        {
            var current = config.GetValueOrDefault("startOnLaunch", "false").ToLowerInvariant() == "true";
            config["startOnLaunch"] = (!current).ToString().ToLowerInvariant();
            SaveTunnelConfig(name, config);
            LogActivity("Tunnels", $"Tunnel '{name}' autostart set to {!current}.");
        }
    }

    public void StopTunnel(string name)
    {
        ClientContext.Inst?.StopTunnel(name);
        LogActivity("Tunnels", $"Stopped tunnel '{name}'.");
    }
}

public class TransitTunnelInfo
{
    public string TunnelId { get; set; } = string.Empty;
    public string FromRouter { get; set; } = string.Empty;
    public string? FromRouterHash { get; set; }
    public string ToRouter { get; set; } = string.Empty;
    public string? ToRouterHash { get; set; }
    public bool IsOutboundEndpoint { get; set; }
    public bool IsInboundGateway { get; set; }
    public int MessageCount { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public float SendBitrateKBps { get; set; }
    public float ReceiveBitrateKBps { get; set; }
    public DateTime LastActivity { get; set; }
}

public class ActivityLogEntry
{
    public DateTime Timestamp { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class RouterStatistics
{
    public string RouterHash { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public TimeSpan Uptime { get; set; }
    public string PublicKey { get; set; } = string.Empty;
    public string KeyType { get; set; } = string.Empty;
    public bool IsRunning { get; set; }

    // Transport statistics
    public int NTCP2SessionCount { get; set; }
    public int SSU2SessionCount { get; set; }

    // NetDb statistics
    public int KnownRouters { get; set; }
    public int KnownFloodfills { get; set; }
    public int KnownLeaseSets { get; set; }

    // Tunnel statistics
    public int InboundTunnels { get; set; }
    public int OutboundTunnels { get; set; }
    public int ExploratoryTunnels { get; set; }
    public int TransitTunnels { get; set; }

    // Bandwidth
    public string InboundBandwidth { get; set; } = "0 Bps";
    public string OutboundBandwidth { get; set; } = "0 Bps";
    public string BandwidthClass { get; set; } = "O";

    // Client services
    public bool SAMEnabled { get; set; }
    public int SAMSessions { get; set; }
    public bool I2CPEnabled { get; set; }
    public bool HTTPProxyEnabled { get; set; }
    public bool SOCKSProxyEnabled { get; set; }
    public bool HTTPProxyRunning { get; set; }
    public int HTTPProxyPort { get; set; }

    public I2PRouterInfo? FullRouterInfo { get; set; }
}