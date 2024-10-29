using MimeKit;

namespace Email.API.Interfaces;

public interface IEmailSender
{
    Task SendAsync(MimeMessage message);
}
