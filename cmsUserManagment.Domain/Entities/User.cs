using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace cms.Domain.Entities;

public class User
{
    [Key]
    public Guid Id { get; init; }
    public required string Email { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
    public bool Has2Fa { get; set; } = false;
    public bool? IsAdmin { get; set; } = false;

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
