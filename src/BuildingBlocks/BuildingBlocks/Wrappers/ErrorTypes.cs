namespace BuildingBlocks.Wrappers;

public enum ErrorType
{
    ValidationError = 1,
    NotFoundError,
    NoAvailableOptionsError,
    AlreadyCreatedError,
    InvalidDataPassedError,
    ExceedingNumberOfRooms,
    EmailNotSentError,
    Unauthorized,
    Forbidden,
    InvalidCredentials,
    ResourceInUse,
    None
}
