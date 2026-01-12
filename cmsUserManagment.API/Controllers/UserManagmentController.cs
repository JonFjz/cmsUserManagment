using cms.Domain.Entities;

using cmsUserManagment.Application.DTO;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using cmsUserManagment.Application.Interfaces;

namespace cmsUserManagment.Controllers;

[Route("api/user")]
[ApiController]
[Authorize(Roles = "admin")]
public class UserManagementController(IUserManagementService userManagementService) : ControllerBase
{
    private readonly IUserManagementService _userManagementService = userManagementService;

    /// <summary>
    /// Gets all users with pagination.
    /// </summary>
    /// <param name="pageNumber">The page number.</param>
    /// <param name="pageSize">The page size.</param>
    /// <returns>A list of users.</returns>
    [HttpGet]
    [ProducesResponseType(typeof(IEnumerable<User>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetAllUsers([FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
    {
        var users = await _userManagementService.GetAllUsers(pageNumber, pageSize);
        return Ok(users);
    }

    /// <summary>
    /// Gets a user by ID.
    /// </summary>
    /// <param name="id">The user ID.</param>
    /// <returns>The user.</returns>
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(User), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetUserById(Guid id)
    {
        var user = await _userManagementService.GetUserById(id);
        return  Ok(user);
    }

    /// <summary>
    /// Searches for users.
    /// </summary>
    /// <param name="username">The username to search for.</param>
    /// <param name="email">The email to search for.</param>
    /// <param name="isAdmin">Filter by admin status.</param>
    /// <param name="orderBy">The field to order by.</param>
    /// <param name="descending">Whether to sort in descending order.</param>
    /// <param name="pageNumber">The page number.</param>
    /// <param name="pageSize">The page size.</param>
    /// <returns>A paginated result of users.</returns>
    [HttpGet("search")]
    [ProducesResponseType(typeof(PaginatedResult<User>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> SearchUsers([FromQuery] string? username, [FromQuery] string? email, [FromQuery] bool? isAdmin, [FromQuery] string? orderBy = "username", [FromQuery] bool descending = false, [FromQuery] int pageNumber = 1, [FromQuery] int pageSize = 10)
    {
        var users = await _userManagementService.SearchUsers(username, email, isAdmin, orderBy, descending, pageNumber, pageSize);
        return Ok(users);
    }

    /// <summary>
    /// Updates a user.
    /// </summary>
    /// <param name="id">The user ID.</param>
    /// <param name="userDto">The user update data.</param>
    /// <returns>True if the update was successful.</returns>
    [HttpPut("{id}")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserDto userDto)
    {
        var result = await _userManagementService.UpdateUser(id, userDto);
        return Ok(result);
    }

    /// <summary>
    /// Deletes a user.
    /// </summary>
    /// <param name="id">The user ID.</param>
    /// <returns>True if the delete was successful.</returns>
    [HttpDelete("{id}")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> DeleteUser(Guid id)
    {
        var result = await _userManagementService.DeleteUser(id);
        return Ok(result);
    }

    /// <summary>
    /// Deletes multiple users.
    /// </summary>
    /// <param name="ids">The list of user IDs to delete.</param>
    /// <returns>True if the delete was successful.</returns>
    [HttpPost("delete-bulk")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> DeleteBulkUsers([FromBody] IEnumerable<Guid> ids)
    {
        var result = await _userManagementService.DeleteBulkUsers(ids);
        return Ok(result);
    }

}
