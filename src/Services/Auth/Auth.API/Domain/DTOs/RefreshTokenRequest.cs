using System.Text.Json.Serialization;

namespace Auth.API.Domain.DTOs;

public class RefreshTokenRequest
{
    public string Token { get; set; }
    [JsonIgnore]
    public string? RefreshToken { get; set; }
}
