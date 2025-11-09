using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace cmsUserManagment.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly IJwtTokenProvider _jwtTokenProvider;

    public AuthController(IAuthenticationService authenticationService, IJwtTokenProvider jwtTokenProvider)
    {
        _authenticationService = authenticationService;
        _jwtTokenProvider = jwtTokenProvider;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterUser user)
    {
        var result = await _authenticationService.Register(user);
        return Ok(result);
    }

    [HttpGet("login")]
    public IActionResult Login(string email, string password)
    {
        var user = _authenticationService.Login(email, password);
        var token = _jwtTokenProvider.GenerateToken(email, "1231231", "admin");
        return Ok(token);
    }
    [HttpGet]
    [Authorize(Roles = "admin")]
    public IActionResult Get()
    {
        return Ok("hello");
    }
}
