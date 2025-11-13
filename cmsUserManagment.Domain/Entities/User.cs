using System.ComponentModel.DataAnnotations;

namespace cms.Domain.Entities;

public class User
{
    [Key] public Guid Id { get; init; }

    [Required][EmailAddress] public required string Email { get; set; }

    public required string Username { get; set; }

    [Required] public required string Password { get; set; }

    public string? TwoFactorSecret { get; set; }

    public bool IsTwoFactorEnabled { get; set; } = false;
    public bool IsAdmin { get; set; } = false;

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
