using System.Text.Json;

using cms.Domain.Entities;
using cmsUserManagment.Application.Common.ErrorCodes;
using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Application.Common.Validation;
using cmsUserManagment.Infrastructure.Persistance;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;

namespace cmsUserManagment.Infrastructure.Repositories;

public class UserManagementService(AppDbContext dbContext, IDistributedCache cache) : IUserManagementService
{
    private readonly AppDbContext _dbContext = dbContext;
    private readonly IDistributedCache _cache = cache;

    public async Task<PaginatedResult<User>> GetAllUsers(int pageNumber, int pageSize)
    {
        var query = _dbContext.Users.AsQueryable();
        var totalCount = await query.CountAsync();
        var items = await query.Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync();

        return new PaginatedResult<User>
        {
            Items = items,
            TotalCount = totalCount,
            PageNumber = pageNumber,
            PageSize = pageSize
        };
    }

    public async Task<User?> GetUserById(Guid id)
    {
        string cacheKey = $"user:{id}";
        string? cachedUser = await _cache.GetStringAsync(cacheKey);

        if (!string.IsNullOrEmpty(cachedUser))
        {
            var userFromCache = JsonSerializer.Deserialize<User>(cachedUser);
            if (userFromCache != null) return userFromCache;
        }

        User? user = await _dbContext.Users.FindAsync(id);
        if (user == null) throw GeneralErrorCodes.NotFound;

        await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(user));
        return user;
    }

    public async Task<bool> UpdateUser(Guid id, UpdateUserDto userDto)
    {
        if (userDto == null) throw GeneralErrorCodes.InvalidInput;

        InputValidator.ValidateUsername(userDto.Username);
        InputValidator.ValidateEmail(userDto.Email);

        User? user = await _dbContext.Users.FindAsync(id);
        if (user == null) throw GeneralErrorCodes.NotFound;

        if (!string.Equals(user.Email, userDto.Email, StringComparison.OrdinalIgnoreCase))
        {
            bool emailTaken = await _dbContext.Users.AnyAsync(u => u.Email == userDto.Email && u.Id != id);
            if (emailTaken) throw GeneralErrorCodes.Conflict;
        }

        string oldEmail = user.Email;

        user.Username = userDto.Username;
        user.Email = userDto.Email;
        user.IsAdmin = userDto.IsAdmin;

        _dbContext.Users.Update(user);
        await _dbContext.SaveChangesAsync();

        await _cache.RemoveAsync($"user:{id}");

        if (!string.Equals(oldEmail, user.Email, StringComparison.OrdinalIgnoreCase))
        {
            await _cache.RemoveAsync($"email:{oldEmail}");
        }

        await UpdateAuthCache(user);

        return true;
    }

    public async Task<bool> DeleteUser(Guid id)
    {
        User? user = await _dbContext.Users.FindAsync(id);
        if (user == null) throw GeneralErrorCodes.NotFound;

        _dbContext.Users.Remove(user);
        await _dbContext.SaveChangesAsync();

        await _cache.RemoveAsync($"user:{id}");
        await _cache.RemoveAsync($"email:{user.Email}");

        return true;
    }

    public async Task<bool> DeleteBulkUsers(IEnumerable<Guid> ids)
    {
        var usersToDelete = await _dbContext.Users.Where(u => ids.Contains(u.Id)).ToListAsync();
        if (usersToDelete.Count == 0) throw GeneralErrorCodes.NotFound;

        _dbContext.Users.RemoveRange(usersToDelete);
        await _dbContext.SaveChangesAsync();

        foreach (var user in usersToDelete)
        {
            await _cache.RemoveAsync($"user:{user.Id}");
            await _cache.RemoveAsync($"email:{user.Email}");
        }

        return true;
    }

    public async Task<IEnumerable<User>> SearchUsers(string? username, string? email, bool? isAdmin,
        string? orderBy = "username", bool descending = false)
    {
        string cacheKey =
            $"search:username={username}&email={email}&isAdmin={isAdmin}&orderBy={orderBy}&desc={descending}";
        string? cachedResult = await _cache.GetStringAsync(cacheKey);

        if (!string.IsNullOrEmpty(cachedResult))
        {
            return JsonSerializer.Deserialize<IEnumerable<User>>(cachedResult) ?? new List<User>();
        }

        var query = _dbContext.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(username)) query = query.Where(u => u.Username.Contains(username));

        if (!string.IsNullOrWhiteSpace(email)) query = query.Where(u => u.Email.Contains(email));

        if (isAdmin.HasValue) query = query.Where(u => u.IsAdmin == isAdmin.Value);

        query = orderBy?.ToLower() switch
        {
            "email" => descending ? query.OrderByDescending(u => u.Email) : query.OrderBy(u => u.Email),
            "isadmin" => descending ? query.OrderByDescending(u => u.IsAdmin) : query.OrderBy(u => u.IsAdmin),
            _ => descending ? query.OrderByDescending(u => u.Username) : query.OrderBy(u => u.Username)
        };

        var users = await query.ToListAsync();

        await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(users),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10) });

        return users;
    }

    private async Task UpdateAuthCache(User user)
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
}
