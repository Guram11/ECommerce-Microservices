using Auth.API.Domain.Models;

namespace Auth.API.Domain.DTOs;

public sealed record RefreshToken
{
    public int Id { get; set; }
    public required string Token { get; set; }
    public DateTime Expires { get; set; }
    public bool IsExpired => DateTime.UtcNow >= Expires;
    public DateTime Created { get; set; }
    public string? CreatedByIp { get; set; }
    public DateTime? Revoked { get; set; }
    public string? RevokedByIp { get; set; }
    public string? ReplacedByToken { get; set; }
    public bool IsActive => Revoked == null && !IsExpired;
    public required string UserId { get; set; }

    // Navigation property back to ApplicationUser
    public ApplicationUser? User { get; set; }
}
