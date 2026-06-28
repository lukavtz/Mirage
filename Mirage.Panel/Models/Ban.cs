using System.ComponentModel.DataAnnotations;

namespace Mirage.Panel.Models;

public class Ban
{
    [Key] public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Ip { get; set; } = "";
    public string? Reason { get; set; }
    public DateTime BannedAt { get; set; } = DateTime.UtcNow;
}
