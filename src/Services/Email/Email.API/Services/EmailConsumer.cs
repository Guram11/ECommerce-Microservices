using BuildingBlocks.Messaging.Events;
using Email.API.Interfaces;
using Email.API.Models;
using MassTransit;

namespace Email.API.Services;
public class EmailConsumer : IConsumer<SendEmailMessage>
{
    private readonly IEmailService _emailService;

    public EmailConsumer(IEmailService emailService)
    {
        _emailService = emailService;
    }

    public async Task Consume(ConsumeContext<SendEmailMessage> context)
    {
        var message = context.Message;

        var emailRequest = new EmailRequest
        {
            To = message.To,
            Subject = message.Subject,
            Body = message.Body,
            From = message.From
        };

        await _emailService.SendAsync(emailRequest);
    }
}

