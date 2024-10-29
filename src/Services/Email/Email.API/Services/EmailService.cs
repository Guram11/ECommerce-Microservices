using BuildingBlocks.Errors;
using BuildingBlocks.Settings;
using BuildingBlocks.Wrappers;
using Email.API.Interfaces;
using Email.API.Models;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Email.API.Services;

public class EmailService : IEmailService
{
    private readonly MailSettings _mailSettings;
    private readonly IEmailSender _emailSender;

    public EmailService(IOptions<MailSettings> mailSettings, IEmailSender emailSender)
    {
        _mailSettings = mailSettings.Value;
        _emailSender = emailSender;
    }

    public async Task<Result<string>> SendAsync(EmailRequest request)
    {
        try
        {
            var builder = new BodyBuilder
            {
                HtmlBody = request.Body
            };

            var email = new MimeMessage
            {
                Sender = new MailboxAddress(_mailSettings.DisplayName, request.From ?? _mailSettings.EmailFrom),
                Subject = request.Subject,
                Body = builder.ToMessageBody()
            };
            email.To.Add(MailboxAddress.Parse(request.To));

            await _emailSender.SendAsync(email);

            return Result<string>.Success(AuthErrors.EmailSentSuccessfully);
        }
        catch (Exception ex)
        {
            return Result<string>.Failure(EmailServiceErrors.EmailNotSent(ex.Message));
        }
    }
}
