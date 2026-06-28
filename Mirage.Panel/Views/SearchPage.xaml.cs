using System.Net.Http;
using System.Text.Json;
using System.Windows.Controls;
using System.Windows.Input;
using Mirage.Panel.Models;

namespace Mirage.Panel.Views;

public partial class SearchPage : Page
{
    private static readonly HttpClient Http = new();

    public SearchPage()
    {
        InitializeComponent();
    }

    private async void DoSearch()
    {
        var q = SearchBox.Text;
        if (string.IsNullOrWhiteSpace(q)) return;

        try
        {
            var json = await Http.GetStringAsync($"http://127.0.0.1:5000/api/search?q={Uri.EscapeDataString(q)}");
            var docs = JsonSerializer.Deserialize<List<Password>>(json) ?? new();
            ResultsGrid.ItemsSource = docs;
        }
        catch { }
    }

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) DoSearch();
    }

    private void SearchClick(object sender, System.Windows.RoutedEventArgs e)
    {
        DoSearch();
    }

    private void ResultsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ResultsGrid.SelectedItem is Password pw)
        {
            NavigationService?.Navigate(new SessionDetailPage(pw.SessionId));
        }
    }
}
