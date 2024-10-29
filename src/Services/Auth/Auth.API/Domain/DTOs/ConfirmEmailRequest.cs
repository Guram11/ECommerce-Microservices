namespace Auth.API.Domain.DTOs;

public class ConfirmEmailRequest
{
    public required string UserId { get; set; }
    public required string Code { get; set; }
}
