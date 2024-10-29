using Auth.API.Domain.DTOs;
using Auth.API.Domain.Models;
using BuildingBlocks.Wrappers;

namespace Auth.API.Interfaces;

public interface IAuthService
{
    Task<Result<AuthenticationResponse>> AuthenticateAsync(AuthenticationRequest request);
    Task<Result<string>> RegisterAsync(CreateUserRequest request);
    Task<Result<string>> ConfirmEmailAsync(ConfirmEmailRequest request);
    Task<Result<string>> DeleteUserAsync(string userId);
    Task<Result<List<ApplicationUser>>> GetAllUsersAsync();
    Task<Result<AuthenticationResponse>> RefreshTokenAsync(string token, string ipAddress);
    Task<Result<string>> RevokeTokenAsync(string token, string ipAddress);
    Task<Result<string>> LogoutAsync(string token, string jwt, string ipAddress);
    //Task<Result<AuthenticationResponse>> ExternalLoginAsync(string provider, string providerKey, string email, string ipAddress);
    //Task<Result<string>> ForgotPassword(ForgotPasswordRequest request);
    //Task<Result<string>> ResetPassword(ResetPasswordRequest request);
}
