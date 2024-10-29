using Auth.API.Domain.DTOs;
using Auth.API.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Auth.API.Controllers;

[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ITokenBlacklistService _tokenBlacklistService;

    public AuthController(IAuthService authService, ITokenBlacklistService tokenBlacklistService)
    {
        _authService = authService;
        _tokenBlacklistService = tokenBlacklistService;
    }

    [HttpGet("blacklist/{token}")]
    public async Task<IActionResult> CheckBlacklist(string token)
    {
        var isRevoked = await _tokenBlacklistService.IsTokenRevokedAsync(token);
        return Ok(isRevoked);
    }

    //[HttpGet("signin-google")]
    //public async Task<IActionResult> GoogleCallback()
    //{
    //    var authenticateResult = await HttpContext.AuthenticateAsync();

    //    if (!authenticateResult.Succeeded)
    //        return BadRequest("Google authentication failed");

    //    // Get the claims (Google user information)
    //    var claims = authenticateResult.Principal?.Identities
    //                   .FirstOrDefault()?.Claims
    //                   .Select(c => new { c.Type, c.Value });

    //    // Extract email from claims
    //    var email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

    //    if (string.IsNullOrEmpty(email))
    //        return BadRequest("Google authentication did not provide an email address");

    //    var googleId = claims?.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

    //    if (string.IsNullOrEmpty(googleId))
    //        return BadRequest("Google authentication did not provide a valid Google ID");

    //    // Use AuthService to handle external login or user registration and JWT generation
    //    var result = await _authService.ExternalLoginAsync("Google", googleId, email, HttpContext.Connection.RemoteIpAddress?.ToString());

    //    if (!result.IsSuccess)
    //        return BadRequest(result.Error);

    //    // Return JWT and user information
    //    return Ok(new
    //    {
    //        Message = "Google login successful",
    //        Token = result.Data.JWToken,
    //        RefreshToken = result.Data.RefreshToken,
    //        result.Data.Email,
    //        result.Data.UserName,
    //        result.Data.Roles
    //    });
    //}

    //// Endpoint to redirect to Google's OAuth2 login page
    //[HttpGet("login-google")]
    //public IActionResult LoginWithGoogle()
    //{
    //    var redirectUrl = Url.Action(nameof(GoogleCallback), "Authentication");
    //    var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
    //    return Challenge(properties, "Google");
    //}

    //private string GenerateJwtToken(string email)
    //{
    //    // Logic to generate JWT token, based on the registered JWT token generation in your AuthService
    //    return "generated-jwt-token"; // Example placeholder
    //}

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var origin = Request.Headers["Origin"].FirstOrDefault();
        request.Origin = origin;
        var result = await _authService.RegisterAsync(request);

        if (result.IsSuccess)
        {
            return Ok(new { Message = "User registered successfully. Please check your email for verification."});
        }

        return BadRequest(result.Error);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Authenticate([FromBody] AuthenticationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var origin = Request.Headers["Origin"].FirstOrDefault();
        request.IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var result = await _authService.AuthenticateAsync(request);

        if (result.IsSuccess)
        {
            return Ok(result.Data);
        }

        return Unauthorized(result.Error);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authService.LogoutAsync(request.RefreshToken, request.Jwt, ipAddress);

        if (!result.IsSuccess)
        {
            return BadRequest(new { message = result.Error });
        }

        return Ok(result.Data);
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var result = await _authService.RefreshTokenAsync(request.Token, ipAddress);
        if (!result.IsSuccess)
        {
            return BadRequest(result.Error);
        }

        return Ok(result.Data);
    }

    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

        var result = await _authService.RevokeTokenAsync(request.Token, ipAddress);
        if (!result.IsSuccess)
        {
            return BadRequest(result.Error);
        }

        return Ok(result.Data);
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
        {
            return BadRequest("Invalid parameters.");
        }

        var result = await _authService.ConfirmEmailAsync(new ConfirmEmailRequest
        {
            UserId = userId,
            Code = code
        });

        if (result.IsSuccess)
        {
            return Ok(new { Message = "Email confirmed successfully." });
        }

        return BadRequest(result.Error);
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var result = await _authService.GetAllUsersAsync();
        if (!result.IsSuccess)
        {
            return NotFound(result.Error);
        }

        return Ok(result.Data);
    }

    [HttpDelete("user/{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var result = await _authService.DeleteUserAsync(id);
        if (!result.IsSuccess)
        {
            return BadRequest(result.Error);
        }

        return Ok(new { Message = $"User with ID {id} deleted successfully." });
    }
}