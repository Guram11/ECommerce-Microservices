namespace Auth.API.Interfaces;

public interface ITokenBlacklistService
{
    Task<bool> IsTokenRevokedAsync(string token);
    Task RevokeTokenAsync(string token, DateTime? expirationDate);
}
