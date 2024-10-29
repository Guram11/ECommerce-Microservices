namespace YarpApiGateway.Middlewares;

public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TokenValidationMiddleware> _logger;

    public TokenValidationMiddleware(RequestDelegate next, IHttpClientFactory httpClientFactory,
        IServiceProvider serviceProvider, ILogger<TokenValidationMiddleware> logger)
    {
        _next = next;
        _httpClientFactory = httpClientFactory;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Extract the token from the Authorization header
        string token = String.Empty;
        if (context.Request.Headers.TryGetValue("Authorization", out var tokenHeader) &&
            tokenHeader.ToString().StartsWith("Bearer "))
        {
            token = tokenHeader.ToString().Substring("Bearer ".Length).Trim();
        }

        // If no token is found, continue to the next middleware without processing
        if (string.IsNullOrEmpty(token))
        {
            await _next(context);
            return;
        }

        using var client = _httpClientFactory.CreateClient();

        try
        {
            // Check if the token is blacklisted
            var response = await client.GetAsync($"http://auth.api:8080/blacklist/{token}");
            response.EnsureSuccessStatusCode();

            var isRevoked = await response.Content.ReadFromJsonAsync<bool>();

            if (isRevoked)
            {
                _logger.LogWarning("Token is blacklisted.");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Token is blacklisted. Please log in again.");
                return;
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError($"Request error: {ex.Message}");
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsync("Internal server error.");
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Unexpected error: {ex.Message}");
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsync("An unexpected error occurred.");
            return;
        }

        _logger.LogWarning("Token is not revoked!!!!");

        // Continue to the next middleware
        await _next(context);
    }
}

