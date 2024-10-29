using System.Text.Json.Serialization;

namespace Auth.API.Domain.DTOs;

public class RevokeTokenRequest
{
    public string Token { get; set; }
    [JsonIgnore]
    public string? IpAddress { get; set; }
}