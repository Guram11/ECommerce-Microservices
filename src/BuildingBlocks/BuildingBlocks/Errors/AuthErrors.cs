using BuildingBlocks.Wrappers;

namespace BuildingBlocks.Errors;

public static class AuthErrors
{
    public static Error UserNotFound(string email) => new Error(
        ErrorType.NotFoundError, $"No accounts registered with the email '{email}'.");

    public static Error NoUsersFound() => new Error(
        ErrorType.NotFoundError, $"No users were found.");

    public static Error UserDeletionFailed(string email) => new Error(
        ErrorType.NotFoundError, $"Deletion failed for user: '{email}'.");

    public static Error InvalidCredentials(string email) => new Error(
        ErrorType.InvalidCredentials, $"Invalid credentials for '{email}'.");

    public static Error EmailNotConfirmed(string email) => new Error(
        ErrorType.NotFoundError, $"Account not confirmed for '{email}'.");

    public static Error TokenGenerationError(string message) => new Error(
        ErrorType.InvalidCredentials, $"Error while generating JWT token: {message}.");

    public static Error UsernameTaken(string username) => new Error(
        ErrorType.NotFoundError, $"Username '{username}' is already taken.");

    public static Error UserAlreadyInRole(string username) => new Error(
        ErrorType.AlreadyCreatedError, $"User: '{username}' is already in role.");

    public static Error PasswordsDoNotMatch() => new Error(
       ErrorType.InvalidDataPassedError, $"Passwords do not match!");

    public static Error EmailRegistered(string email) => new Error(
        ErrorType.AlreadyCreatedError, $"Email '{email}' is already registered.");

    public static Error EmailConfirmationFailed(string email) => new Error(
        ErrorType.EmailNotSentError, $"An error occurred while confirming the email '{email}'.");

    public static Error PasswordResetFailed(string email) => new Error(
        ErrorType.NotFoundError, $"Error occurred while resetting the password for '{email}'.");

    public static Error UserCreationFailed(string error) => new Error(
        ErrorType.NotFoundError, $"UserCreationFailed: '{error}'.");

    public static Error Unauthorized() => new Error(
        ErrorType.Unauthorized, "You are not Authorized!");

    public static Error InvalidToken() => new Error(
    ErrorType.Unauthorized, "Invalid token!");

    public static Error TokenNoLongerActive() => new Error(
    ErrorType.Unauthorized, "Token is no longer active!");

    public static Error Forbidden() => new Error(
        ErrorType.Forbidden, "You are not authorized to access this resource");

    public static Error EmailNotSent(string message) => new Error(
        ErrorType.EmailNotSentError, $"An error has occurred while sending an email. '{message}'.");

    public static string EmailSentSuccessfully = "Email sent successfully.";
}
