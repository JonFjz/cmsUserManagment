using cmsUserManagment.Application.DTO;

using Google.Authenticator;

namespace cmsUserManagment.Application.Interfaces;

public interface IAuthenticationService
{
    public Task<object?> Login(string email, string password);
    public Task<bool> Register(RegisterUser user);
    public Task<string?> RefreshToken(Guid refreshToken, string jwtToken);
    public Task Logout(string jwtToken, Guid rt);
    public Task<string?> twoFactorAuthentication(Guid loginId, string key);
    public Task<SetupCode> generateAuthToken(string jwtToken);
    public Task<bool> disableTwoFactorAuth(string jwtToken);
}
