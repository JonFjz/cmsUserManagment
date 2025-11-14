using System.Security.Cryptography;
using System.Text.Json;

using cms.Domain.Entities;

using cmsUserManagment.Application.Common.ErrorCodes;
using cmsUserManagment.Application.Common.Validation;
using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Infrastructure.Persistance;
using cmsUserManagment.Infrastructure.Security;

using Google.Authenticator;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;

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
        InputValidator.ValidateEmail(email);
        InputValidator.ValidatePassword(password);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Email == email);
        if (user == null || !PasswordHelper.VerifyPassword(password, user.Password))
            throw new GeneralErrorCodes(GeneralErrorCodes.NotFound.Code, GeneralErrorCodes.NotFound.Message);

        return await GetRightToken(user);
    }


    public async Task<bool> Register(RegisterUser user)
    {
        InputValidator.ValidateEmail(user.Email);
        InputValidator.ValidatePassword(user.Password);
        InputValidator.ValidateUsername(user.Username);

        string key = $"email:{user.Email}";

        if (await _cache.GetStringAsync(key) != null ||
            await _dbContext.Users.AnyAsync(e => e.Email == user.Email))
            throw new GeneralErrorCodes(GeneralErrorCodes.Conflict.Code, GeneralErrorCodes.Conflict.Message);

        User newUser = new()
        {
            Email = user.Email, Username = user.Username, Password = PasswordHelper.HashPassword(user.Password)
        };

        await _dbContext.Users.AddAsync(newUser);
        await _dbContext.SaveChangesAsync();
        await UpdateCache(newUser);

        return true;
    }

    public async Task<string> RefreshToken(Guid refreshToken, string jwtToken)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        RefreshToken? refreshTokenObj = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(e => e.UserId == userId && e.Id == refreshToken);

        if (refreshTokenObj == null)
            throw new AuthErrorCodes(AuthErrorCodes.TokenNotFound.Code, AuthErrorCodes.TokenNotFound.Message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);

        if (user == null || refreshTokenObj.Expires < DateTime.UtcNow)
            throw new GeneralErrorCodes(GeneralErrorCodes.NotFound.Code, GeneralErrorCodes.NotFound.Message);

        string newToken = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);

        await UpdateCache(user);

        return newToken;
    }

    public async Task Logout(string jwtToken, Guid rt)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);

        if (userId == Guid.Empty)
            throw new AuthErrorCodes(AuthErrorCodes.BadToken.Code, AuthErrorCodes.BadToken.Message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);

        if (user == null)
            throw new GeneralErrorCodes(GeneralErrorCodes.NotFound.Code, GeneralErrorCodes.NotFound.Message);

        RefreshToken? refreshToken =
            await _dbContext.RefreshTokens.FirstOrDefaultAsync(e => e.UserId == userId && e.Id == rt);

        if (refreshToken == null)
            throw new AuthErrorCodes(AuthErrorCodes.FailedToLogOut.Code, AuthErrorCodes.FailedToLogOut.Message);

        _dbContext.RefreshTokens.Remove(refreshToken);
        await _cache.RemoveAsync($"email:{user.Email}");
        await _dbContext.SaveChangesAsync();
    }

    public async Task<bool> TwoFactorAuthenticationConfirm(string jwtToken, string code)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null)
            throw new AuthErrorCodes(AuthErrorCodes.TokenNotFound.Code, AuthErrorCodes.TokenNotFound.Message);

        TwoFactorAuthenticator tfa = new();
        if (!tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, code))
            throw new AuthErrorCodes(AuthErrorCodes.InvalidVerificationCode.Code,
                AuthErrorCodes.InvalidVerificationCode.Message);

        user.IsTwoFactorEnabled = true;
        await _dbContext.SaveChangesAsync();
        await UpdateCache(user);

        return true;
    }

    public async Task<LoginCredentials> TwoFactorAuthenticationLogin(Guid loginId, string code)
    {
        TwoFactorAuthCodes? token = await _dbContext.TwoFactorAuthCodes.FirstOrDefaultAsync(e => e.Id == loginId);
        if (token == null || token.Expires < DateTime.UtcNow)
            throw new AuthErrorCodes(AuthErrorCodes.TokenNotFound.Code, AuthErrorCodes.TokenNotFound.Message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == token.UserId);
        if (user == null)
            throw new GeneralErrorCodes(GeneralErrorCodes.NotFound.Code, GeneralErrorCodes.NotFound.Message);

        TwoFactorAuthenticator tfa = new();
        if (!tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, code))
            throw new AuthErrorCodes(AuthErrorCodes.InvalidVerificationCode.Code,
                AuthErrorCodes.InvalidVerificationCode.Message);

        string jwtToken = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);
        RefreshToken refreshtoken = new() { UserId = user.Id };

        _dbContext.TwoFactorAuthCodes.Remove(token);
        await _dbContext.RefreshTokens.AddAsync(refreshtoken);
        await _dbContext.SaveChangesAsync();
        await UpdateCache(user);

        return new LoginCredentials { jwtToken = jwtToken, refreshToken = refreshtoken.Id.ToString() };
    }

    public async Task<SetupCode> GenerateAuthToken(string jwtToken)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw new ArgumentNullException(nameof(user));

        byte[] secretKeyBytes = new byte[32];
        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        rng.GetBytes(secretKeyBytes);

        string key = Base32Encoding.ToString(secretKeyBytes);

        TwoFactorAuthenticator tfa = new();
        SetupCode setupInfo = tfa.GenerateSetupCode("cms", user.Email, key, false);

        user.TwoFactorSecret = key;

        await _dbContext.SaveChangesAsync();
        await UpdateCache(user);

        return setupInfo;
    }

    public async Task<bool> DisableTwoFactorAuth(string jwtToken)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw new ArgumentNullException(nameof(user));

        user.IsTwoFactorEnabled = false;

        await _dbContext.SaveChangesAsync();
        await UpdateCache(user);

        return true;
    }

    private async Task UpdateCache(User user)
    {
        var cachedUser = new
        {
            user.Id,
            user.Email,
            user.Username,
            user.IsAdmin,
            user.IsTwoFactorEnabled
        };

        string key = $"email:{user.Email}";

        await _cache.SetStringAsync(key, JsonSerializer.Serialize(cachedUser));
    }

    private async Task<object> GetRightToken(User user)
    {
        if (!user.IsTwoFactorEnabled)
        {
            string token = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);
            RefreshToken refreshtoken = new() { UserId = user.Id };

            await _dbContext.RefreshTokens.AddAsync(refreshtoken);
            await _dbContext.SaveChangesAsync();

            await UpdateCache(user);

            return new LoginCredentials { jwtToken = token, refreshToken = refreshtoken.Id.ToString() };
        }

        TwoFactorAuthCodes twoFactorCode = new() { UserId = user.Id };

        await _dbContext.TwoFactorAuthCodes.AddAsync(twoFactorCode);
        await _dbContext.SaveChangesAsync();

        await UpdateCache(user);

        return new { twoFactorToken = twoFactorCode.Id.ToString() };
    }
}
