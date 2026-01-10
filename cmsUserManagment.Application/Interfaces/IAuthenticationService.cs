using System.Threading.Tasks;
using cmsUserManagment.Application.DTO;

using Google.Authenticator;

namespace cmsUserManagment.Application.Interfaces;

public interface IAuthenticationService
{
    public Task<object> Login(string email, string password);
    public Task<bool> Register(RegisterUser user);
    public Task<string> RefreshToken(Guid refreshToken, string jwtToken);
    public Task Logout(string jwtToken, Guid rt);
    public Task<LoginCredentials> TwoFactorAuthenticationLogin(Guid loginId, string code);
    public Task<bool> TwoFactorAuthenticationConfirm(string jwtToken, string code);
    public Task<SetupCode> GenerateAuthToken(string jwtToken);
    public Task<bool> DisableTwoFactorAuth(string jwtToken);
    public Task<bool> UpdateAccount(string jwtToken, UpdateAccountRequest request);
    public Task<object> GetUserInfo(string jwtToken);
}
