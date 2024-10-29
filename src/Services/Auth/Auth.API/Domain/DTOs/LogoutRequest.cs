namespace Auth.API.Domain.DTOs;

public class LogoutRequest
{
    public required string RefreshToken { get; set; }
    public required string Jwt { get; set; }
}
