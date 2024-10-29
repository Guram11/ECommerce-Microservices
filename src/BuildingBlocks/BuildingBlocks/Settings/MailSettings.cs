namespace BuildingBlocks.Settings;

public class MailSettings
{
    public required string EmailFrom { get; set; }
    public required string SmtpHost { get; set; }
    public int SmtpPort { get; set; }
    public required string SmtpUser { get; set; }
    public required string SmtpPass { get; set; }
    public required string DisplayName { get; set; }
    public string? ConfirmEmailBody { get; set; }
    public string? ConfirmEmailSubject { get; set; }
    public string? ConfirmEmailRoute { get; set; }
    public string? ResetEmailBody { get; set; }
    public string? ResetEmailSubject { get; set; }
    public string? ResetEmailRoute { get; set; }

}
