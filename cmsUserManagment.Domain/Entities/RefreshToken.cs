using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace cms.Domain.Entities;

public class RefreshToken
{
    [Key]
    public Guid Id { get; init; }

    public required string Token { get; init; }
    public DateTime Expires { get; init; }

    [ForeignKey(nameof(User))]
    public Guid UserId { get; init; }
    public required User User { get; init; }
}
