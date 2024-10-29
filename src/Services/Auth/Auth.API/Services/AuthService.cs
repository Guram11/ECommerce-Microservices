using Auth.API.Data;
using Auth.API.Domain.DTOs;
using Auth.API.Domain.Enums;
using Auth.API.Domain.Models;
using Auth.API.Helpers;
using Auth.API.Interfaces;
using BuildingBlocks.Errors;
using BuildingBlocks.Messaging.Events;
using BuildingBlocks.Settings;
using BuildingBlocks.Wrappers;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.API.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly MailSettings _mailSettings;
    private readonly JWTSettings _jwtSettings;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILogger<AuthService> _logger;
    private readonly DataContext _context;
    private readonly ITokenBlacklistService _tokenBlacklistService;

    public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWTSettings> jwtSettings,
        IOptions<MailSettings> mailSettings, SignInManager<ApplicationUser> signInManager,
        IPublishEndpoint publishEndpoint, ILogger<AuthService> logger, DataContext context, ITokenBlacklistService tokenBlacklistService)
    {
        _userManager = userManager;
        _mailSettings = mailSettings.Value;
        _jwtSettings = jwtSettings.Value;
        _signInManager = signInManager;
        _publishEndpoint = publishEndpoint;
        _logger = logger;
        _context = context;
        _tokenBlacklistService = tokenBlacklistService;
    }

    public async Task<Result<AuthenticationResponse>> AuthenticateAsync(AuthenticationRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.UserNotFound(request.Email));
        }

        if (user.UserName is null || user.Email is null)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.InvalidCredentials(request.Email));
        }

        var signInResult = await _signInManager.PasswordSignInAsync(user.UserName, request.Password, false, lockoutOnFailure: false);
        if (!signInResult.Succeeded)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.InvalidCredentials(request.Email));
        }

        if (!user.EmailConfirmed)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.EmailNotConfirmed(request.Email));
        }

        try
        {
            // Revoke existing refresh tokens
            await RevokeExistingRefreshTokens(user.Id);

            // Generate JWT token
            var jwtToken = await GenerateJWToken(user);

            // Generate new refresh token
            var refreshToken = GenerateRefreshToken(request.IpAddress, user.Id);
            refreshToken.UserId = user.Id;

            await _context.RefreshTokens.AddAsync(refreshToken); // Use DbContext to add
            await _context.SaveChangesAsync();

            var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var response = new AuthenticationResponse
            {
                Id = user.Id,
                JWToken = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                Email = user.Email,
                UserName = user.UserName,
                Roles = rolesList.ToList(),
                IsVerified = user.EmailConfirmed,
                RefreshToken = refreshToken.Token
            };

            return Result<AuthenticationResponse>.Success(response);
        }
        catch (Exception ex)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.TokenGenerationError(ex.Message));
        }
    }

    public async Task<Result<AuthenticationResponse>> RefreshTokenAsync(string token, string ipAddress)
    {
        var user = await GetUserByRefreshToken(token);
        if (user == null || user.UserName is null || user.Email is null)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.InvalidToken());
        }

        // Fetch the refresh token from the database
        var refreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == token && x.UserId == user.Id);

        if (refreshToken is null)
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.InvalidToken());
        }

        // Check if the refresh token is active
        if (!refreshToken.IsActive) // Here we can use the computed property
        {
            return Result<AuthenticationResponse>.Failure(AuthErrors.TokenNoLongerActive());
        }

        // Replace old refresh token with a new one
        var newRefreshToken = GenerateRefreshToken(ipAddress, user.Id);
        refreshToken.Revoked = DateTime.UtcNow;
        refreshToken.RevokedByIp = ipAddress;
        refreshToken.ReplacedByToken = newRefreshToken.Token;
        user.RefreshTokens.Add(newRefreshToken);
        var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);

        await _userManager.UpdateAsync(user);

        var jwtToken = await GenerateJWToken(user);

        var response = new AuthenticationResponse
        {
            Id = user.Id,
            Email = user.Email,
            UserName = user.UserName,
            Roles = rolesList.ToList(),
            IsVerified = user.EmailConfirmed,
            JWToken = new JwtSecurityTokenHandler().WriteToken(jwtToken),
            RefreshToken = newRefreshToken.Token,
        };

        return Result<AuthenticationResponse>.Success(response);
    }

    public async Task<Result<string>> RevokeTokenAsync(string token, string ipAddress)
    {
        var user = await GetUserByRefreshToken(token);
        if (user == null)
        {
            return Result<string>.Failure(AuthErrors.InvalidToken());
        }

        var refreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == token && x.UserId == user.Id);

        if (refreshToken is null)
        {
            return Result<string>.Failure(AuthErrors.InvalidToken());
        }

        // Check if the refresh token is active
        if (!refreshToken.IsActive)
        {
            return Result<string>.Failure(AuthErrors.TokenNoLongerActive());
        }

        // Revoke the token
        refreshToken.Revoked = DateTime.UtcNow;
        refreshToken.RevokedByIp = ipAddress;

        await _userManager.UpdateAsync(user);
        await _context.SaveChangesAsync();

        return Result<string>.Success("Token revoked.");
    }

    private async Task RevokeExistingRefreshTokens(string userId)
    {
        var tokens = await _context.RefreshTokens.Where(rt => rt.UserId == userId).ToListAsync();
        var existingTokens = tokens.Where(rt => rt.IsActive).ToList();

        foreach (var token in existingTokens)
        {
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = IpHelper.GetIpAddress(); // Use the current IP address
        }
        await _context.SaveChangesAsync(); // Save changes to revoke tokens
    }

    private async Task<ApplicationUser?> GetUserByRefreshToken(string token)
    {
        return await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(rt => rt.Token == token));
    }

    public async Task<Result<string>> LogoutAsync(string token, string jwt, string ipAddress)
    {
        var refreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken is null || !refreshToken.IsActive)
        {
            return Result<string>.Failure(AuthErrors.TokenNoLongerActive());
        }

        // Revoke refresh token
        refreshToken.Revoked = DateTime.UtcNow;
        refreshToken.RevokedByIp = ipAddress;
        await _context.SaveChangesAsync();

        // Revoke access token
        await _tokenBlacklistService.RevokeTokenAsync(jwt, DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes));

        return Result<string>.Success("Logged out successfully.");
    }

    public async Task<Result<string>> RegisterAsync(CreateUserRequest request)
    {
        var userWithSameUserName = await _userManager.FindByNameAsync(request.UserName);
        if (userWithSameUserName != null)
        {
            return Result<string>.Failure(AuthErrors.UsernameTaken(request.UserName));
        }

        var userWithSameEmail = await _userManager.FindByEmailAsync(request.Email);
        if (userWithSameEmail != null)
        {
            return Result<string>.Failure(AuthErrors.EmailRegistered(request.Email));
        }

        if (request.Password != request.PasswordConfirm)
        {
            return Result<string>.Failure(AuthErrors.PasswordsDoNotMatch());
        }

        var user = new ApplicationUser
        {
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            UserName = request.UserName
        };

        var createUserResult = await _userManager.CreateAsync(user, request.Password);
        if (!createUserResult.Succeeded)
        {
            var errors = string.Join(", ", createUserResult.Errors.Select(e => e.Description));
            return Result<string>.Failure(AuthErrors.UserCreationFailed(errors));
        }

        await _userManager.AddToRoleAsync(user, Roles.Basic.ToString());
        var verificationUri = await SendVerificationEmail(user, request.Origin);

        try
        {
            var emailMessage = new SendEmailMessage
            {
                To = user.Email,
                Subject = "Welcome!",
                Body = $"{_mailSettings.ConfirmEmailBody} {verificationUri}",
                From = _mailSettings.EmailFrom
            };

            await _publishEndpoint.Publish(emailMessage);

            return Result<string>.Success(user.Id);
        }
        catch (Exception ex)
        {
            return Result<string>.Failure(EmailServiceErrors.EmailNotSent(ex.Message));
        }
    }

    public async Task<Result<string>> ConfirmEmailAsync(ConfirmEmailRequest request)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null || user.Email is null)
        {
            return Result<string>.Failure(AuthErrors.UserNotFound(request.UserId));
        }

        var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Code));
        var result = await _userManager.ConfirmEmailAsync(user, code);

        if (result.Succeeded)
        {
            return Result<string>.Success(user.Id);
        }
        else
        {
            return Result<string>.Failure(AuthErrors.EmailConfirmationFailed(user.Email));
        }
    }

    public async Task<Result<List<ApplicationUser>>> GetAllUsersAsync()
    {
        var users = await _userManager.Users.ToListAsync();

        return Result<List<ApplicationUser>>.Success(users);
    }

    public async Task<Result<string>> DeleteUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            return Result<string>.Failure(AuthErrors.UserNotFound(userId));
        }

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            return Result<string>.Failure(AuthErrors.UserDeletionFailed(user.Email!));
        }

        return Result<string>.Success(userId);
    }

    //public async Task<Result<string>> ForgotPassword(ForgotPasswordRequest model)
    //{
    //    var account = await _userManager.FindByEmailAsync(model.Email);

    //    if (account is null)
    //    {
    //        return Result<string>.Failure(AccountServiceErrors.UserNotFound(model.Email));
    //    };

    //    var code = await _userManager.GeneratePasswordResetTokenAsync(account);
    //    var route = _mailSettings.ResetEmailRoute;
    //    var _enpointUri = new Uri(string.Concat($"{model.Origin}/", route));

    //    var emailRequest = new EmailRequest
    //    {
    //        Body = $"{_mailSettings.ResetEmailBody} {code}",
    //        To = model.Email,
    //        Subject = _mailSettings.ResetEmailSubject!
    //    };

    //    try
    //    {
    //        await _emailService.SendAsync(emailRequest);
    //        return Result<string>.Success(SuccessResponses.EmailSentSuccessfully);
    //    }
    //    catch (Exception ex)
    //    {
    //        return Result<string>.Failure(EmailServiceErrors.EmailNotSent(ex.Message));
    //    }
    //}

    //public async Task<Result<string>> ResetPassword(ResetPasswordRequest model)
    //{
    //    var account = await _userManager.FindByEmailAsync(model.Email);
    //    if (account == null)
    //    {
    //        return Result<string>.Failure(AccountServiceErrors.UserNotFound(model.Email));
    //    }

    //    var result = await _userManager.ResetPasswordAsync(account, model.Token, model.Password);

    //    if (result.Succeeded)
    //    {
    //        return Result<string>.Success(model.Email);
    //    }
    //    else
    //    {
    //        return Result<string>.Failure(AccountServiceErrors.PasswordResetFailed(model.Email));
    //    }
    //} 

    private async Task<string> SendVerificationEmail(ApplicationUser user, string? origin)
    {
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
        var route = _mailSettings.ConfirmEmailRoute;
        var _enpointUri = new Uri(string.Concat($"{origin}/", route));
        var verificationUri = QueryHelpers.AddQueryString(_enpointUri.ToString(), "userId", user.Id);
        verificationUri = $"https://localhost:6064/auth-service/confirm-email?userId={user.Id}&code={code}";

        return verificationUri;
    }

    private async Task<JwtSecurityToken> GenerateJWToken(ApplicationUser user)
    {
        var userClaims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        var roleClaims = new List<Claim>();
        for (int i = 0; i < roles.Count; i++)
        {
            roleClaims.Add(new Claim("roles", roles[i]));
        }

        string ipAddress = IpHelper.GetIpAddress();

        if (user.UserName is null || user.Email is null)
        {
            throw new Exception($"Invalid Credentials for '{user.Email}'.");
        }

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("uid", user.Id),
            new Claim("ip", ipAddress)
        }
        .Union(userClaims)
        .Union(roleClaims);

        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
            signingCredentials: signingCredentials);

        return jwtSecurityToken;
    }

    private string RandomTokenString()
    {
        var randomBytes = new byte[40];
        RandomNumberGenerator.Fill(randomBytes);
        return BitConverter.ToString(randomBytes).Replace("-", "");
    }

    private RefreshToken GenerateRefreshToken(string? ipAddress, string userId)
    {
        return new RefreshToken
        {
            UserId = userId,
            Token = RandomTokenString(),
            Expires = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };
    }
}
