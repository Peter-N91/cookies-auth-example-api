namespace cookies_auth_example_api.Controllers;

using Microsoft.AspNetCore.Mvc;
using cookies_auth_example_api.Authorization;
using cookies_auth_example_api.Models;
using cookies_auth_example_api.Services;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.Cookies;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;
    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate([FromBody] AuthenticateModel model)
    {
        var user = await _userService.Authenticate(model.Username, model.Password);

        if (user == null)
            return BadRequest(new { message = "Username or password is incorrect" });

        var userId = Guid.NewGuid().ToString();
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userId),
            new Claim("firstname1", "spiderman"),
            new Claim("access_token", GetAccessToken(userId))
        };

        var claimsIdentity = new ClaimsIdentity(
          claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties();
        /*
        AuthenticationProperties drive further auth cookie behavior in the browser. 
        For example, the IsPersistent property persists the cookie across browser sessions. 
        Be sure to get explicit user consent when you enable this property. 
        ExpiresUtc sets an absolute expiration, be sure to enable IsPersistent and set it to true.
        */

        await HttpContext.SignInAsync(
          CookieAuthenticationDefaults.AuthenticationScheme,
          new ClaimsPrincipal(claimsIdentity),
          authProperties);
        return Ok(user);
    }

    [HttpGet("username")]
    public async Task<IActionResult> GetUserName()
    {
        var me = HttpContext.User;
        return Ok(me.Claims.FirstOrDefault(c=>c.Type == "firstname1")?.Value);
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var users = await _userService.GetAll();
        return Ok(users);
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok();
    }

    private static string GetAccessToken(string userId)
    {
        const string issuer = "localhost";
        const string audience = "localhost";

        var identity = new ClaimsIdentity(new List<Claim>
        {
            new Claim("sub", userId),
            new Claim("firstname", "batman")
        });

        var bytes = Encoding.UTF8.GetBytes(userId);
        var key = new SymmetricSecurityKey(bytes);
        var signingCredentials = new SigningCredentials(
          key, SecurityAlgorithms.HmacSha256);

        var now = DateTime.UtcNow;
        var handler = new JwtSecurityTokenHandler();

        var token = handler.CreateJwtSecurityToken(
          issuer, audience, identity,
          now, now.Add(TimeSpan.FromSeconds(60)),
          now, signingCredentials);

        return handler.WriteToken(token);

        /*
        Don’t ever do this is in production. 
        Here, I use the user id as the signing key which is symmetric to keep it simple. 
        In a prod environment use an asymmetric signing key with public and private keys. 
        Client apps will then use a well-known configuration endpoint to validate the JWT.
        */
    }
}