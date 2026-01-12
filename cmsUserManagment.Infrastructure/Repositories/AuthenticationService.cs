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
    JwtDecoder jwtDecoder) : IAuthenticationService
{
    private readonly IDistributedCache _cache = cache;
    private readonly AppDbContext _dbContext = dbContext;
    private readonly JwtDecoder _jwtDecoder = jwtDecoder;
    private readonly IJwtTokenProvider _jwtTokenProvider = jwtTokenProvider;

    public async Task<object> Login(string email, string password)
    {
        InputValidator.ValidateEmail(email);
        InputValidator.ValidatePassword(password);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Email == email);
        if (user == null || !PasswordHelper.VerifyPassword(password, user.Password)) throw GeneralErrorCodes.NotFound;

        if (!user.IsTwoFactorEnabled)
        {
            string token = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);
            RefreshToken refreshtoken = new() { UserId = user.Id };
            await _dbContext.RefreshTokens.AddAsync(refreshtoken);
            await _dbContext.SaveChangesAsync();
            await UpdateCache(user);
            return new {
                jwtToken = token,
                refreshToken = refreshtoken.Id.ToString(),
                twoFactorId = (string?)null
            };
        }
        else
        {
            TwoFactorAuthCode twoFactorCode = new() { UserId = user.Id };
            await _dbContext.TwoFactorAuthCodes.AddAsync(twoFactorCode);
            await _dbContext.SaveChangesAsync();
            await UpdateCache(user);
            return new {
                jwtToken = (string?)null,
                refreshToken = (string?)null,
                twoFactorId = twoFactorCode.Id.ToString()
            };
        }
    }

    public async Task<bool> Register(RegisterUser user)
    {
        InputValidator.ValidateEmail(user.Email);
        InputValidator.ValidatePassword(user.Password);
        InputValidator.ValidateUsername(user.Username);

        string key = $"email:{user.Email}";

        if (await _cache.GetStringAsync(key) != null || await _dbContext.Users.AnyAsync(e => e.Email == user.Email))
            throw GeneralErrorCodes.Conflict;

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
        RefreshToken? refreshTokenObj =
            await _dbContext.RefreshTokens.FirstOrDefaultAsync(e => e.UserId == userId && e.Id == refreshToken);

        if (refreshTokenObj == null) throw AuthErrorCodes.TokenNotFound;

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);

        if (user == null || refreshTokenObj.Expires < DateTime.UtcNow) throw GeneralErrorCodes.NotFound;

        string newToken = _jwtTokenProvider.GenerateToken(user.Email, user.Id.ToString(), user.IsAdmin);

        await UpdateCache(user);

        return newToken;
    }

    public async Task Logout(string jwtToken, Guid refreshToken)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        if (userId == Guid.Empty) throw AuthErrorCodes.BadToken;

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw GeneralErrorCodes.NotFound;

        RefreshToken? tokenObj = await _dbContext.RefreshTokens.FirstOrDefaultAsync(e => e.UserId == userId && e.Id == refreshToken);
        if (tokenObj == null) throw AuthErrorCodes.FailedToLogOut;

        _dbContext.RefreshTokens.Remove(tokenObj);
        await _cache.RemoveAsync($"email:{user.Email}");
        await _dbContext.SaveChangesAsync();
    }

    public async Task<bool> TwoFactorAuthenticationConfirm(string jwtToken, string code)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw AuthErrorCodes.TokenNotFound;

        TwoFactorAuthenticator tfa = new();
        if (!tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, code)) throw AuthErrorCodes.InvalidVerificationCode;

        user.IsTwoFactorEnabled = true;
        await _dbContext.SaveChangesAsync();
        await UpdateCache(user);

        return true;
    }

    public async Task<LoginCredentials> TwoFactorAuthenticationLogin(Guid loginId, string code)
    {
        TwoFactorAuthCode? token = await _dbContext.TwoFactorAuthCodes.FirstOrDefaultAsync(e => e.Id == loginId);
        if (token == null || token.Expires < DateTime.UtcNow)
            throw new AuthErrorCodes(AuthErrorCodes.TokenNotFound.Code, AuthErrorCodes.TokenNotFound.Message);

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == token.UserId);
        if (user == null) throw GeneralErrorCodes.NotFound;

        TwoFactorAuthenticator tfa = new();
        if (!tfa.ValidateTwoFactorPIN(user.TwoFactorSecret, code)) throw AuthErrorCodes.InvalidVerificationCode;

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
        if (user == null) throw GeneralErrorCodes.NotFound;

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
        if (user == null) throw GeneralErrorCodes.NotFound;

        user.IsTwoFactorEnabled = false;
        user.TwoFactorSecret = null;

        await _dbContext.SaveChangesAsync();
        await UpdateCache(user);

        return true;
    }

    public async Task<bool> UpdateAccount(string jwtToken, UpdateAccountRequest request)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        if (userId == Guid.Empty) throw AuthErrorCodes.BadToken;

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        if (user == null) throw GeneralErrorCodes.NotFound;

        string oldEmail = user.Email;
        bool emailChanged = false;
        bool anyChange = false;

        if (!string.IsNullOrWhiteSpace(request.Email) &&
            !string.Equals(request.Email, user.Email, StringComparison.OrdinalIgnoreCase))
        {
            InputValidator.ValidateEmail(request.Email);
            bool exists = await _dbContext.Users.AnyAsync(e => e.Email == request.Email && e.Id != user.Id);
            if (exists) throw GeneralErrorCodes.Conflict;

            user.Email = request.Email!;
            emailChanged = true;
            anyChange = true;
        }

        if (!string.IsNullOrWhiteSpace(request.Username) &&
            !string.Equals(request.Username, user.Username, StringComparison.Ordinal))
        {
            InputValidator.ValidateUsername(request.Username);
            user.Username = request.Username!;
            anyChange = true;
        }

        if (!string.IsNullOrWhiteSpace(request.NewPassword))
        {
            InputValidator.ValidatePassword(request.NewPassword!);

            if (string.IsNullOrWhiteSpace(request.CurrentPassword) ||
                !PasswordHelper.VerifyPassword(request.CurrentPassword!, user.Password))
                throw AuthErrorCodes.InvalidCredentials;

            user.Password = PasswordHelper.HashPassword(request.NewPassword!);
            anyChange = true;
        }

        if (!anyChange) return true;

        await _dbContext.SaveChangesAsync();

        if (emailChanged) await _cache.RemoveAsync($"email:{oldEmail}");

        await UpdateCache(user);
        return true;
    }

    public async Task<object> GetUserInfo(string jwtToken)
    {
        Guid userId = _jwtDecoder.GetUserid(jwtToken);
        if (userId == Guid.Empty) throw AuthErrorCodes.BadToken;

        User? user = await _dbContext.Users.FirstOrDefaultAsync(e => e.Id == userId);
        
        if (user == null)
            throw new GeneralErrorCodes(GeneralErrorCodes.NotFound.Code, GeneralErrorCodes.NotFound.Message);

        return new { user.Username, user.Email, hasTwoFactorAuth = user.IsTwoFactorEnabled };
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

        TwoFactorAuthCode twoFactorCode = new() { UserId = user.Id };

        await _dbContext.TwoFactorAuthCodes.AddAsync(twoFactorCode);
        await _dbContext.SaveChangesAsync();

        await UpdateCache(user);

        // Instead of returning an anonymous object, throw a specific exception for two-factor required
        throw AuthErrorCodes.TwoFactorRequired;
    }
}
