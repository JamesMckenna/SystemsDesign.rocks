using IdentityServer4.Configuration;
using Microsoft.Extensions.Configuration;
using System;

namespace IS4.AppConfiguration
{
    internal static  class AppIS4Options
    {
        internal static IConfiguration _configuration;
        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        internal static void App_IS4_Options(IdentityServerOptions options)
        {
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseInformationEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseSuccessEvents = true;
            
            // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
            options.EmitStaticAudienceClaim = true;

            options.Csp.Level = IdentityServer4.Models.CspLevel.Two;

            //Session Cookie
            options.Authentication.CheckSessionCookieName = _configuration["Properties:SharedSessionCookie"];
            options.Authentication.CookieLifetime = TimeSpan.FromSeconds(Double.Parse(_configuration["LifeTimes:SessionCookieExpireSeconds"].ToString()));

            options.Authentication.CookieSlidingExpiration = true;

            options.Authentication.RequireCspFrameSrcForSignout = false;

            options.Cors.CorsPolicyName = "IS4";
        }
    }
}
