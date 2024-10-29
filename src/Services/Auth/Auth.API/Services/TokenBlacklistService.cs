using Auth.API.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using System.Security.Cryptography;
using System.Text;

namespace Auth.API.Services;

public class TokenBlacklistService : ITokenBlacklistService
{
    private readonly IDistributedCache _cache;
    private readonly ILogger<TokenBlacklistService> _logger;

    public TokenBlacklistService(IDistributedCache cache, ILogger<TokenBlacklistService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public async Task<bool> IsTokenRevokedAsync(string token)
    {
        var isRevoked = await _cache.GetStringAsync(GetCacheKey(token));
        return !string.IsNullOrEmpty(isRevoked);
    }

    public async Task RevokeTokenAsync(string token, DateTime? expirationDate)
    {
        var cacheOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = expirationDate ?? DateTime.UtcNow.AddMinutes(30)
        };
        await _cache.SetStringAsync(GetCacheKey(token), "revoked", cacheOptions);
        _logger.LogInformation($"Token {token} revoked and will expire at {cacheOptions.AbsoluteExpiration}.");
    }

    private string GetCacheKey(string token) => $"revoked_token_{ComputeHash(token)}";

    private string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(bytes);
    }
}
