using System.Windows;
using System.Windows.Controls;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mirage.Panel.Data;
using Mirage.Panel.Services;

namespace Mirage.Panel.Views;

public partial class SettingsPage : Page
{
    private readonly PanelServer _server;

    public SettingsPage()
    {
        InitializeComponent();
        _server = ((App)Application.Current).Services.GetRequiredService<PanelServer>();
        ServerPort.Text = _server.Port.ToString();
        AuthTokenDisplay.Text = _server.AuthToken;
        LoadDbStats();
    }

    private void LoadDbStats()
    {
        try
        {
            var factory = ((App)Application.Current).Services.GetService(typeof(IDbContextFactory<AppDbContext>))
                as IDbContextFactory<AppDbContext>;
            if (factory == null) return;

            using var db = factory.CreateDbContext();
            var total = db.Sessions.Count();
            var oldest = db.Sessions.OrderBy(s => s.CreatedAt).FirstOrDefault();
            var newest = db.Sessions.OrderByDescending(s => s.CreatedAt).FirstOrDefault();

            DbTotalSessions.Text = $"Total Sessions: {total}";
            DbOldestSession.Text = oldest != null
                ? $"Oldest: {oldest.Ip ?? "N/A"} — {oldest.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC"
                : "Oldest: N/A";
            DbNewestSession.Text = newest != null
                ? $"Newest: {newest.Ip ?? "N/A"} — {newest.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC"
                : "Newest: N/A";
        }
        catch { }
    }

    private void SaveClick(object sender, RoutedEventArgs e)
    {
        if (int.TryParse(ServerPort.Text, out var port))
        {
            typeof(PanelServer).GetProperty(nameof(PanelServer.Port))?.SetValue(_server, port);
            StatusText.Text = "Port updated. Restart to apply.";
        }
    }

    private void RegenerateTokenClick(object sender, RoutedEventArgs e)
    {
        var newToken = Guid.NewGuid().ToString("N");
        typeof(PanelServer).GetProperty(nameof(PanelServer.AuthToken))?.SetValue(_server, newToken);
        AuthTokenDisplay.Text = newToken;
        StatusText.Text = "Auth token regenerated.";
    }

    private void RestartClick(object sender, RoutedEventArgs e)
    {
        _server.Stop();
        _server.Start();
        StatusText.Text = "Server restarted.";
    }
}
