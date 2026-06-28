using System.Net.Http;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.EntityFrameworkCore;
using Mirage.Panel.Data;

namespace Mirage.Panel.Views;

public partial class DashboardPage : Page
{
    private static readonly HttpClient Http = new();
    private readonly DispatcherTimer _timer;

    public DashboardPage()
    {
        InitializeComponent();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += async (_, _) => await RefreshStats();
        _timer.Start();
        Unloaded += (_, _) => _timer.Stop();
        _ = RefreshStats();
    }

    private async Task RefreshStats()
    {
        try
        {
            var json = await Http.GetStringAsync("http://127.0.0.1:5000/api/stats");
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            SessionsToday.Text = root.GetProperty("today").GetInt32().ToString();
            TotalPasswords.Text = root.GetProperty("passwords").GetInt32().ToString();
            TotalCookies.Text = root.GetProperty("cookies").GetInt32().ToString();
            TotalWallets.Text = root.GetProperty("wallets").GetInt32().ToString();
            TotalSessions.Text = root.GetProperty("sessions").GetInt32().ToString();
            TotalCards.Text = root.GetProperty("cards").GetInt32().ToString();
        }
        catch { }

        try
        {
            var factory = ((App)Application.Current).Services.GetService(typeof(IDbContextFactory<AppDbContext>))
                as IDbContextFactory<AppDbContext>;
            if (factory == null) return;

            using var db = factory.CreateDbContext();
            var last = await db.Sessions.OrderByDescending(s => s.CreatedAt).FirstOrDefaultAsync();
            LastSessionInfo.Text = last != null
                ? $"{last.Ip ?? "N/A"} — {last.Os ?? "N/A"} — {last.Username ?? "N/A"} — {last.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC"
                : "No sessions yet";
        }
        catch { }
    }
}
