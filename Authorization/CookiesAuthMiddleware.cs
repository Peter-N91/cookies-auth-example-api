namespace cookies_auth_example_api.Authorization;

using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using cookies_auth_example_api.Services;

public class CookiesAuthMiddleware
{
    private readonly RequestDelegate _next;

    public CookiesAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context, IUserService userService)
    {
        var principal = context.User as ClaimsPrincipal;
        var fn = principal?.Claims.FirstOrDefault(c=>c.Type == "firstname1");
        var accessToken = principal?.Claims
          .FirstOrDefault(c => c.Type == "access_token");

        await _next(context);
    }
}