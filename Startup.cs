using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using cookies_auth_example_api.Authorization;
using cookies_auth_example_api.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace cookies_auth_example_api;

public class Startup
{
    public const string CookieScheme = "YourSchemeName";
    IWebHostEnvironment _environment;
    public Startup(IConfiguration configuration, IWebHostEnvironment environment)
    {
        Configuration = configuration;
        _environment = environment;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();

        services.Configure<CookiePolicyOptions>(options =>
            {
                options.MinimumSameSitePolicy = SameSiteMode.Strict;
                options.HttpOnly = HttpOnlyPolicy.None;
                options.Secure = _environment.IsDevelopment()
                    ? CookieSecurePolicy.None : CookieSecurePolicy.Always;
            });

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme) // Sets the default scheme to cookies
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.HttpOnly = true; // cookie is only available to servers. The browser only sends the cookie but cannot access it through JavaScript.
                options.Cookie.SecurePolicy = _environment.IsDevelopment() ? CookieSecurePolicy.None : CookieSecurePolicy.Always; // Use Always on prod. On dev it is better to use None
                options.Cookie.SameSite = _environment.IsDevelopment() ? SameSiteMode.Strict : SameSiteMode.Lax; // Use Lax if using OAuth for single site you need Strict
            });

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();

        services.AddMemoryCache();
        services.AddScoped<IUserService, UserService>();
        services.AddTransient<ITicketStore, InMemoryTicketStore>();
        services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>, ConfigureMyCookie>();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseCors(x => x
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader());

        app.UseStaticFiles();

        app.UseRouting();

        app.UseHttpsRedirection();

        app.UseCookiePolicy();
        app.UseAuthentication();

        app.UseMiddleware<CookiesAuthMiddleware>();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapDefaultControllerRoute();
        });
    }
}