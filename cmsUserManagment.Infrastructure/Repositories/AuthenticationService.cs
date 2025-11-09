using System.Text.Json;

using cms.Domain.Entities;

using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;

using Microsoft.Extensions.Caching.Distributed;

namespace cmsUserManagment.Infrastructure.Repositories;

public class AuthenticationService(IDistributedCache cache) : IAuthenticationService
{
    private readonly IDistributedCache _cache = cache;
    public object? Login(string email, string password)
    {
        var key = $"email:{email}";
        var user = _cache.GetString(key);
        if (user == null)
            return null;
        var userObj = JsonSerializer.Deserialize<User>(user);
        if (userObj == null)
            return null;

        return userObj;
    }

    public async Task<bool> Register(RegisterUser user)
    {
        var key = $"email:{user.Email}";
        var newUser = new User
        {
            Email = user.Email,
            Username = user.Username,
            Password = user.Password,
            Has2Fa = user.Has2Fa,
            IsAdmin = false,
            Id = default
        };

        await _cache.SetStringAsync(key, JsonSerializer.Serialize(newUser));
        return true;
    }

    public string RefreshToken(string token)
    {
        throw new NotImplementedException();
    }

    public void Logout(string token)
    {
        throw new NotImplementedException();
    }

    public string twoFactorAuthentication(string loginId)
    {
        throw new NotImplementedException();
    }
}
