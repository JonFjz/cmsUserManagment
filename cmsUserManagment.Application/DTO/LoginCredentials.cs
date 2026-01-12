namespace cmsUserManagment.Application.DTO;

public class LoginCredentials
{
    public string? jwtToken { get; set; }
    public string? refreshToken { get; set; }
}
