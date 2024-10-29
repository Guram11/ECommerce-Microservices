using System.Text.Json.Serialization;

namespace Auth.API.Domain.DTOs;

public sealed record AuthenticationResponse
{
    public required string Id { get; init; }
    public required string UserName { get; init; }
    public required string Email { get; init; }
    public required List<string> Roles { get; init; }
    public bool IsVerified { get; init; }
    public required string JWToken { get; init; }
    public string? RefreshToken { get; init; }
}
