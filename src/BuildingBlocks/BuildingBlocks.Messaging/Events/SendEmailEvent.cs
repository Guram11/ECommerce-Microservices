namespace BuildingBlocks.Messaging.Events;

public record SendEmailMessage : IntegrationEvent
{
    public string To { get; set; } = default!;
    public string Subject { get; set; } = default!;
    public string Body { get; set; } = default!;
    public string From { get; set; } = default!;
}
