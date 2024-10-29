namespace Email.API.Models;

public sealed record EmailRequest
{
    public required string To { get; init; }
    public required string Subject { get; init; }
    public required string Body { get; init; }
    public string? From { get; init; }
}
