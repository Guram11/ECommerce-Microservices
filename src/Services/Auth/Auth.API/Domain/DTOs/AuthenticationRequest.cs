using System.Text.Json.Serialization;

namespace Auth.API.Domain.DTOs;

public sealed record AuthenticationRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    [JsonIgnore]
    public string? IpAddress { get; set; }
}
