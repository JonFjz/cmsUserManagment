using cms.Domain.Entities;

using cmsUserManagment.Application.DTO;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using cmsUserManagment.Application.Interfaces;

namespace cmsUserManagment.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize(Roles = "admin")]
public class UserManagementController(IUserManagementService userManagementService) : ControllerBase
{
    private readonly IUserManagementService _userManagementService = userManagementService;

    [HttpGet]
    public async Task<IActionResult> GetAllUsers([FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
    {
        var users = await _userManagementService.GetAllUsers(pageNumber, pageSize);
        return Ok(users);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetUserById(Guid id)
    {
        var user = await _userManagementService.GetUserById(id);
        return  Ok(user);
    }

    [HttpGet("search")]
    public async Task<IActionResult> SearchUsers([FromQuery] string? username, [FromQuery] string? email, [FromQuery] bool? isAdmin, [FromQuery] string? orderBy = "username", [FromQuery] bool descending = false)
    {
        var users = await _userManagementService.SearchUsers(username, email, isAdmin, orderBy, descending);
        return Ok(users);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserDto userDto)
    {
        var result = await _userManagementService.UpdateUser(id, userDto);
        return Ok(result);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        var result = await _userManagementService.DeleteUser(id);
        return Ok(result);
    }

    [HttpPost("delete-bulk")]
    public async Task<IActionResult> DeleteBulkUsers([FromBody] IEnumerable<Guid> ids)
    {
        var result = await _userManagementService.DeleteBulkUsers(ids);
        return Ok(result);
    }

}
