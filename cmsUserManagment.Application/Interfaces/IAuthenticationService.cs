using cms.Domain.Entities;

using cmsUserManagment.Application.DTO;

namespace cmsUserManagment.Application.Interfaces;


public interface IAuthenticationService
{
    public object? Login(string email, string password);
    public Task<bool> Register(RegisterUser user);
    public string RefreshToken(string token);
    public void Logout(string token);
    public string twoFactorAuthentication(string loginId);
}
