using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Infrastructure.Security;

using Google.Authenticator;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace cmsUserManagment.Controllers;

[Route("api/User")]
[ApiController]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly HeadersManager _headersManager;
    private readonly IJwtTokenProvider _jwtTokenProvider;

    public AuthController(IAuthenticationService authenticationService, IJwtTokenProvider jwtTokenProvider,
        HeadersManager headersManager)
    {
        _authenticationService = authenticationService;
        _jwtTokenProvider = jwtTokenProvider;
        _headersManager = headersManager;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<bool> Register([FromBody] RegisterUser newUser)
    {
        return await _authenticationService.Register(newUser);
    }

    [HttpGet("login")]
    [AllowAnonymous]
    public async Task<object> Login(string email, string password)
    {
        return await _authenticationService.Login(email, password);
    }

    [HttpPost("logout")]
    public async Task<bool> Logout([FromBody] Guid refreshToken)
    {
        string jwt = _headersManager.GetJwtFromHeader(Request.Headers);

        await _authenticationService.Logout(jwt, refreshToken);
        return true;
    }

    [HttpGet("refresh-token")]
    public async Task<string> RefreshToken(Guid refreshToken)
    {
        return await _authenticationService.RefreshToken(refreshToken,
            _headersManager.GetJwtFromHeader(Request.Headers));
    }

    [HttpPost("generate-two-factor-auth-code")]
    public async Task<SetupCode> GenerateTwoFactorAuthSetupCode()
    {
        return await _authenticationService.GenerateAuthToken(_headersManager.GetJwtFromHeader(Request.Headers));
    }

    [HttpPost("two-factor-auth-confirm")]
    public async Task<bool> TwoFactorAuthenticationConfirm([FromBody] string code)
    {
        return await _authenticationService.TwoFactorAuthenticationConfirm(
            _headersManager.GetJwtFromHeader(Request.Headers), code);
    }

    [HttpDelete("disable-two-factor-auth")]
    public async Task<bool> DisableTwoFactorAuth()
    {
        return await _authenticationService.DisableTwoFactorAuth(_headersManager.GetJwtFromHeader(Request.Headers));
    }

    [HttpPost("login-with-two-factor-auth")]
    [AllowAnonymous]
    public async Task<LoginCredentials> TwoFactorAuthenticationLogin(string loginId, string code)
    {
        return await _authenticationService.TwoFactorAuthenticationLogin(Guid.Parse(loginId), code);
    }

    [HttpPut("update-account")]
    public async Task<bool> UpdateAccount([FromBody] UpdateAccountRequest request)
    {
        return await _authenticationService.UpdateAccount(_headersManager.GetJwtFromHeader(Request.Headers), request);
    }

    [HttpGet("account-info")]
    public async Task<object> GetAccountInfo()
    {
        return await _authenticationService.GetUserInfo(_headersManager.GetJwtFromHeader(Request.Headers));
    }
}
