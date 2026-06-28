using System.Windows;
using System.Windows.Controls;
using Mirage.Panel.Services;

namespace Mirage.Panel;

public partial class MainWindow : Window
{
    private readonly ResourceExtractor _extractor;

    public MainWindow(ResourceExtractor extractor)
    {
        _extractor = extractor;
        InitializeComponent();
        MainFrame.Navigate(new Views.DashboardPage());
    }

    private void NavChanged(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton rb && rb.Tag is string tag)
        {
            MainFrame.Navigate(tag switch
            {
                "Dashboard" => new Views.DashboardPage(),
                "Sessions" => new Views.SessionsPage(),
                "Build" => new Views.BuildPage(_extractor),
                "Search" => new Views.SearchPage(),
                "Settings" => new Views.SettingsPage(),
                _ => new Views.DashboardPage()
            });
        }
    }
}
