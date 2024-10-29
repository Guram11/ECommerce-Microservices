namespace Email.API.DTOs;

public class SendEmailDto
{
    public required string To { get; set; }
    public required string Subject { get; set; }
    public required string Body { get; set; }
}
