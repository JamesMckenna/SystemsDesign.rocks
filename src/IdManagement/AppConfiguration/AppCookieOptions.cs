using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace IdManagement.AppConfiguration
{
    internal static class AppCookieOptions
    {
        private static IConfiguration _configuration;

        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        internal static void CookieAuthOptions(CookieAuthenticationOptions options)
        {
            options.AccessDeniedPath = new PathString("/Account/AccessDenied");

            options.ClaimsIssuer = _configuration["AppURLS:IS4BaseUrl"];

            options.Cookie.Name = _configuration["Properties:SharedAuthCookie"];
            options.Cookie.HttpOnly = true;
            options.Cookie.Path = "/";
            options.Cookie.IsEssential = true;

            options.Events = new CookieAuthenticationEvents()
            {
                OnSigningOut = async (e) => { await e.HttpContext.RevokeUserRefreshTokenAsync(); }
            };


            #region Part 2 of session cookie lifetime, Part 1 in OIDC Options
            //setting of the ticket that is stored inside the cookie
            options.ExpireTimeSpan = TimeSpan.FromSeconds(Double.Parse(_configuration["LifeTimes:AuthCookieExpireSeconds"].ToString()));
            options.SlidingExpiration = true;
            #endregion

            options.LoginPath = new PathString("/Account/Login");

            options.LogoutPath = new PathString("/Account/Logout");

            options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;

            var protectionProvider = DataProtectionProvider.Create(new DirectoryInfo(_configuration["SECRETS_DIR"]),
            options =>
            {
                options.SetApplicationName(_configuration["Properties:ApplicationName"]);
            });

            options.DataProtectionProvider = protectionProvider;

            var protector = protectionProvider.CreateProtector("CookieProtector");
            options.TicketDataFormat = new TicketDataFormat(protector);
        }

        internal static void CookiePolicy(CookiePolicyOptions options)
        {
            options.CheckConsentNeeded = context => false;
            options.MinimumSameSitePolicy = SameSiteMode.Strict;
            options.Secure = CookieSecurePolicy.Always;
            options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
        }
    }
}
