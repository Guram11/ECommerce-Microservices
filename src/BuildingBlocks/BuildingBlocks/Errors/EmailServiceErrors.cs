using BuildingBlocks.Wrappers;

namespace BuildingBlocks.Errors;

public static class EmailServiceErrors
{
    public static Error EmailNotSent(string message) => new Error(
        ErrorType.EmailNotSentError, $"An error has occurred while sending an email. '{message}'.");
}
