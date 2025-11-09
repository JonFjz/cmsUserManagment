namespace cmsUserManagment.Application.DTO;

public class RegisterUser
{
    public required string Email { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
    public required bool Has2Fa { get; set; }
}
