using BuildingBlocks.Wrappers;
using Email.API.Models;

namespace Email.API.Interfaces;

public interface IEmailService
{
    Task<Result<string>> SendAsync(EmailRequest request);
}
