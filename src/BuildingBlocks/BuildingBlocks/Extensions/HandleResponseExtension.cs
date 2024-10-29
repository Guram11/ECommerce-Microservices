using BuildingBlocks.Wrappers;
using Microsoft.AspNetCore.Mvc;

namespace BuildingBlocks.Extensions;

public static class ResponseHandler
{
    public static ActionResult HandleResponse<T>(Result<T> response)
    {
        if (response.IsSuccess)
        {
            return new OkObjectResult(response);
        }

        return response.Error.ErrorType switch
        {
            ErrorType.ValidationError => new BadRequestObjectResult(response),
            ErrorType.NoAvailableOptionsError => new BadRequestObjectResult(response),
            ErrorType.InvalidDataPassedError => new BadRequestObjectResult(response),
            ErrorType.AlreadyCreatedError => new BadRequestObjectResult(response),
            ErrorType.ExceedingNumberOfRooms => new BadRequestObjectResult(response),
            ErrorType.EmailNotSentError => new BadRequestObjectResult(response),
            ErrorType.Unauthorized => new UnauthorizedObjectResult(response),
            ErrorType.Forbidden => new BadRequestObjectResult(response),
            ErrorType.InvalidCredentials => new BadRequestObjectResult(response),
            ErrorType.ResourceInUse => new BadRequestObjectResult(response),
            ErrorType.NotFoundError => new NotFoundObjectResult(response),
            _ => new StatusCodeResult(500)
        };
    }
}
