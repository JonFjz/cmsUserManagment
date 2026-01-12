using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Infrastructure.Security;

using Google.Authenticator;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace cmsUserManagment.Controllers;

[Route("api/auth")]
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
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<object> Register([FromBody] RegisterUser newUser)
    {
        var success = await _authenticationService.Register(newUser);
        return new { success };
    }

    /// <summary>
    /// Logs in a user.
    /// </summary>
    /// <param name="email">The email of the user.</param>
    /// <param name="password">The password of the user.</param>
    /// <returns>A JWT token if successful.</returns>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> Login([FromBody] LoginUser loginRequest)
    {
        return await _authenticationService.Login(loginRequest.Email, loginRequest.Password);
    }

    /// <summary>
    /// Logs out a user using their refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <returns>True if logout was successful.</returns>
    [HttpPost("logout")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> Logout([FromBody] LogoutRequest request)
    {
        string jwt = _headersManager.GetJwtFromHeader(Request.Headers);
        await _authenticationService.Logout(jwt, request.RefreshToken);
        return new { success = true };
    }

    /// <summary>
    /// Refreshes the JWT token.
    /// </summary>
    /// <param name="refreshToken">The refresh token.</param>
    /// <returns>A new JWT token.</returns>
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var jwtToken = await _authenticationService.RefreshToken(request.RefreshToken,
            _headersManager.GetJwtFromHeader(Request.Headers));
        return new { jwtToken };
    }

    /// <summary>
    /// Generates a two-factor authentication setup code.
    /// </summary>
    /// <returns>The setup code and QR code URL.</returns>
    [HttpPost("2fa/setup")]
    [ProducesResponseType(typeof(SetupCode), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> GenerateTwoFactorAuthSetupCode()
    {
        var setupCode = await _authenticationService.GenerateAuthToken(_headersManager.GetJwtFromHeader(Request.Headers));
        return new { setupCode };
    }

    /// <summary>
    /// Confirms the two-factor authentication setup.
    /// </summary>
    /// <param name="code">The confirmation code.</param>
    /// <returns>True if confirmation was successful.</returns>
    [HttpPost("2fa/confirm")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> TwoFactorAuthenticationConfirm([FromBody] TwoFactorCodeInput input)
    {
        var success = await _authenticationService.TwoFactorAuthenticationConfirm(
            _headersManager.GetJwtFromHeader(Request.Headers), input.code);
        return new { success };
    }

    /// <summary>
    /// Disables two-factor authentication.
    /// </summary>
    /// <returns>True if disabled successfully.</returns>
    [HttpDelete("2fa/disable")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> DisableTwoFactorAuth()
    {
        var success = await _authenticationService.DisableTwoFactorAuth(_headersManager.GetJwtFromHeader(Request.Headers));
        return new { success };
    }

    /// <summary>
    /// Logs in using two-factor authentication.
    /// </summary>
    /// <param name="loginId">The login ID.</param>
    /// <param name="code">The two-factor authentication code.</param>
    /// <returns>The login credentials.</returns>
    [HttpPost("2fa/login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(LoginCredentials), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> TwoFactorAuthenticationLogin([FromBody] TwoFactorLoginRequest request)
    {
        var credentials = await _authenticationService.TwoFactorAuthenticationLogin(request.LoginId, request.Code);
        return new { jwtToken = credentials.jwtToken, refreshToken = credentials.refreshToken };
    }

    /// <summary>
    /// Updates the user's account information.
    /// </summary>
    /// <param name="request">The update request.</param>
    /// <returns>True if the update was successful.</returns>
    [HttpPut("account")]
    [ProducesResponseType(typeof(bool), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> UpdateAccount([FromBody] UpdateAccountRequest request)
    {
        var success = await _authenticationService.UpdateAccount(_headersManager.GetJwtFromHeader(Request.Headers), request);
        return new { success };
    }

    /// <summary>
    /// Gets the user's account information.
    /// </summary>
    /// <returns>The account information.</returns>
    [HttpGet("account")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<object> GetAccountInfo()
    {
        var info = await _authenticationService.GetUserInfo(_headersManager.GetJwtFromHeader(Request.Headers));
        return new { info };
    }
}
