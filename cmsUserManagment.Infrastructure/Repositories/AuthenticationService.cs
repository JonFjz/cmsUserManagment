using System.Text.Json;

using cms.Domain.Entities;

using cmsUserManagment.Application.Common.ErrorCodes;
using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Infrastructure.Persistance;
using cmsUserManagment.Infrastructure.Security;

using Google.Authenticator;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace cmsUserManagment.Infrastructure.Repositories;

public class AuthenticationService(
    IDistributedCache cache,
    AppDbContext dbContext,
    IJwtTokenProvider jwtTokenProvider,
    JwtDecoder jwtDecoder)
    : IAuthenticationService
{
    private readonly IDistributedCache _cache = cache;
    private readonly AppDbContext _dbContext = dbContext;
    private readonly JwtDecoder _jwtDecoder = jwtDecoder;
    private readonly IJwtTokenProvider _jwtTokenProvider = jwtTokenProvider;

    public async Task<object?> Login(string email, string password)
    {
        string key = $"email:{email}";

        string? cachedUser = _cache.GetString(key);
        if (cachedUser != null)
        {
            User? userObj = JsonSerializer.Deserialize<User>(cachedUser);
            if (userObj != null) return await getRightToken(userObj);
        }

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Email == email && e.Password == password)!;

        if (user == null)
            throw new GeneralErrorCodes(GeneralErrorCodes.notFound.code, GeneralErrorCodes.notFound.message);

        await _cache.SetStringAsync(key, JsonSerializer.Serialize(user));

        return await getRightToken(user);
    }

    public async Task<bool> Register(RegisterUser user)
    {
        string key = $"email:{user.Email}";

        if (await _cache.GetStringAsync(key) != null) throw new GeneralErrorCodes(GeneralErrorCodes.exists.code, GeneralErrorCodes.exists.message);

        if (await _dbContext.Users.AnyAsync(e => e.Email == user.Email)) throw new GeneralErrorCodes(GeneralErrorCodes.exists.code, GeneralErrorCodes.exists.message);

        User newUser = new()
        {
            Email = user.Email,
            Username = user.Username,
            Password = user.Password
        };

        await _dbContext.Users.AddAsync(newUser);
        await _dbContext.SaveChangesAsync();
        await _cache.SetStringAsync(key, JsonSerializer.Serialize(newUser));

        return true;
    }

    public async Task<string?> RefreshToken(Guid refreshToken, string jwtToken)
    {
        Guid userId = jwtDecoder.GetUserid(jwtToken);
        RefreshToken? refreshTokenObj = _dbContext.RefreshTokens.FirstOrDefault(e => e.UserId == userId && e.Id == refreshToken);

        if (refreshTokenObj == null) throw new AuthErrorCodes(AuthErrorCodes.tokenNotFound.code, AuthErrorCodes.tokenNotFound.message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);

        if (user == null || refreshTokenObj.Expires < DateTime.Now) throw new GeneralErrorCodes(GeneralErrorCodes.notFound.code, GeneralErrorCodes.notFound.message);

        string newToken = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);

        return newToken;
    }

    public async Task Logout(string jwtToken, Guid rt)
    {
        Guid userId = jwtDecoder.GetUserid(jwtToken);

        if (userId == Guid.Empty)
            throw new AuthErrorCodes(AuthErrorCodes.badToken.code, AuthErrorCodes.badToken.message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        RefreshToken? refreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(e => e.UserId == userId && e.Id == rt);

        if (refreshToken == null)
            throw new AuthErrorCodes(AuthErrorCodes.failedToLogOut.code, AuthErrorCodes.failedToLogOut.message);
        _dbContext.RefreshTokens.Remove(refreshToken);
        await _cache.RemoveAsync($"email:{user.Email}");
        await _dbContext.SaveChangesAsync();
    }

    public async Task<string?> twoFactorAuthentication(Guid loginId, string code)
    {
        TwoFactorAuthCodes? token = _dbContext.TwoFactorAuthCodes.FirstOrDefault(e => e.Id == loginId);
        if (token != null && token.Expires > DateTime.Now)
            throw new AuthErrorCodes(AuthErrorCodes.tokenNotFound.code, AuthErrorCodes.tokenNotFound.message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == token.UserId);
        if (user == null)
            throw new GeneralErrorCodes(GeneralErrorCodes.notFound.code, GeneralErrorCodes.notFound.message);


        TwoFactorAuthenticator tfa = new();
        bool result = tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, code);

        if (!result)
            throw new AuthErrorCodes(AuthErrorCodes.notCorrectCode.code, AuthErrorCodes.notCorrectCode.message);
        _dbContext.TwoFactorAuthCodes.Remove(token);
        await _dbContext.SaveChangesAsync();

        string jwtToken = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);

        return jwtToken;
    }

    public async Task<SetupCode> generateAuthToken(string jwtToken)
    {
        Guid userId = jwtDecoder.GetUserid(jwtToken);
        User user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw new ArgumentNullException(nameof(user));

        // TODO has this key so its harder to guess
        string key = user.Email;

        TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();

        SetupCode setupInfo = tfa.GenerateSetupCode("cms", user.Email, key, false);

        user.TwoFactorSecret = setupInfo.ManualEntryKey;
        await _dbContext.SaveChangesAsync();

        return setupInfo;
    }

    public async Task<bool> disableTwoFactorAuth(string jwtToken)
    {
        Guid userId = jwtDecoder.GetUserid(jwtToken);
        User user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw new ArgumentNullException(nameof(user));

        user.IsTwoFactorEnabled = false;
        await _dbContext.SaveChangesAsync();
        return true;
    }

    public async Task<object?> getRightToken(User user)
    {
        if (!user.IsTwoFactorEnabled)
        {
            string token = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);
            RefreshToken refreshtoken = new()
            {
                UserId = user.Id
            };

            await _dbContext.RefreshTokens.AddAsync(refreshtoken);
            await _dbContext.SaveChangesAsync();

            LoginCredentials refreshTokens = new() { jwtToken = token, refreshToken = refreshtoken.Id.ToString() };
            return refreshTokens;
        }

        TwoFactorAuthCodes twoFactorCode = new() { UserId = user.Id };

        await _dbContext.TwoFactorAuthCodes.AddAsync(twoFactorCode);
        await _dbContext.SaveChangesAsync();

        return new { twoFactorToken = twoFactorCode.Id.ToString() };
    }
}
