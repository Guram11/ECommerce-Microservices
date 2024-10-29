using System.Text.Json.Serialization;

namespace Auth.API.Domain.DTOs;

public class CreateUserRequest
{
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public required string Email { get; set; }
    public required string UserName { get; set; }
    public required string Password { get; set; }
    public required string PasswordConfirm { get; set; }
    [JsonIgnore]
    public string? Origin { get; set; }
}
