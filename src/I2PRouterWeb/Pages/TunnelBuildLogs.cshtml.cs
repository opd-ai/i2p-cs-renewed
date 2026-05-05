using I2PCore.TunnelLayer;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace I2PRouterWeb.Pages;

public class TunnelBuildLogsModel : PageModel
{
    public IEnumerable<TunnelBuildLogger.LogEntry> LogEntries { get; private set; } = Enumerable.Empty<TunnelBuildLogger.LogEntry>();

    public void OnGet()
    {
        LogEntries = TunnelBuildLogger.Inst.GetEntries();
    }
}