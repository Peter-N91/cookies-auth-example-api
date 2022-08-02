using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace cookies_auth_example_api;

internal class ConfigureMyCookie : IPostConfigureOptions<CookieAuthenticationOptions>
{
    private readonly ITicketStore _ticketStore;
    // You can inject services here
    public ConfigureMyCookie(ITicketStore ticketStore)
    {
        _ticketStore = ticketStore;
    }

    public void PostConfigure(string name, CookieAuthenticationOptions options)
    {
        // Only configure the schemes you want
        if (name == CookieAuthenticationDefaults.AuthenticationScheme)
        {
            options.AccessDeniedPath = "/account/denied";
            options.LoginPath = "/account/login";
            options.Cookie.Name = "my_auth_cookie_example";
            options.SessionStore = _ticketStore;
        }
    }

    public void PostConfigure(CookieAuthenticationOptions options)
        => PostConfigure(Options.DefaultName, options);
}