using System.Windows;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Mirage.Panel.Data;
using Mirage.Panel.Services;

namespace Mirage.Panel;

public partial class App : Application
{
    private IHost? _host;
    private CancellationTokenSource? _serverCts;
    public IServiceProvider Services => _host?.Services ?? throw new InvalidOperationException();

    protected override void OnStartup(StartupEventArgs e)
    {
        _serverCts = new CancellationTokenSource();

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddDbContextFactory<AppDbContext>(opts =>
                    opts.UseSqlite("Data Source=mirage_panel.db"));
                services.AddSingleton<PanelServer>();
                services.AddSingleton<BuildService>();
                services.AddSingleton<LogProcessor>();
                services.AddSingleton<TelegramProxy>();
                services.AddSingleton<ResourceExtractor>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        using (var scope = _host.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.EnsureCreated();
        }

        var server = _host.Services.GetRequiredService<PanelServer>();
        server.Start();

        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serverCts?.Cancel();
        try
        {
            _host?.Services.GetRequiredService<PanelServer>().Stop();
        }
        catch { }
        _host?.Dispose();
        base.OnExit(e);
    }
}
