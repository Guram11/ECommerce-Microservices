using BuildingBlocks.Settings;
using Email.API.Interfaces;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Email.API.Services;

public class SmtpEmailSender : IEmailSender
{
    private readonly MailSettings _mailSettings;

    public SmtpEmailSender(IOptions<MailSettings> mailSettings)
    {
        _mailSettings = mailSettings.Value;
    }

    public async Task SendAsync(MimeMessage message)
    {
        using var smtpClient = new SmtpClient();
        smtpClient.Connect(_mailSettings.SmtpHost, _mailSettings.SmtpPort, SecureSocketOptions.StartTls);
        smtpClient.Authenticate(_mailSettings.SmtpUser, _mailSettings.SmtpPass);
        await smtpClient.SendAsync(message);
        smtpClient.Disconnect(true);
    }
}
