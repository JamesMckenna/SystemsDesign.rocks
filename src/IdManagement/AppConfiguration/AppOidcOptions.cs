using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;

namespace IdManagement.AppConfiguration
{
    internal static class AppOidcOptions
    {
        private static IConfiguration _configuration;

        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        internal static void OpenIdOptions(OpenIdConnectOptions options)
        {
            options.Authority = _configuration["AppURLS:IS4BaseUrl"];
            options.ClientId = _configuration["ApplicationIds:IdManagementId"];
            options.ClientSecret = _configuration["ApplicationSecrets:IdManagementSecret"];
            options.ResponseType = "code";
            options.UsePkce = true;
            options.ResponseMode = "query";
            options.GetClaimsFromUserInfoEndpoint = true;//keeps id_token smaller
            options.SaveTokens = true;
            options.SignedOutCallbackPath = new PathString("/signout-callback-oidc");

            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = "role"
            };

            options.Scope.Add(_configuration["ApplicationIds:IdApiId"]);
            options.Scope.Add("offline_access");
            options.Scope.Add("email");
            options.ClaimActions.MapJsonKey("website", "website");

            options.RequireHttpsMetadata = true;

            options.UseTokenLifetime = true;


            //options.Events.OnAuthorizationCodeReceived

            options.Events.OnTicketReceived = (context) =>//IF ticket is Identity Ticket (Authentication)
            {
                context.Properties.IssuedUtc = DateTime.UtcNow;
                //Part 1 of Session cookie lifetime. Part 2 is in cookie options
                //setting of the ticket that is stored inside the cookie
                //This ticket determines the validity of the users authentication session
                double expireSeconds = Double.Parse(_configuration["LifeTimes:AuthCookieExpireSeconds"].ToString());
                context.Properties.ExpiresUtc = DateTime.UtcNow.AddSeconds(expireSeconds);

                context.Properties.IsPersistent = false;
                context.Properties.AllowRefresh = true;
                return Task.CompletedTask;
            };

            options.Events = new OpenIdConnectEvents
            {
                OnRemoteFailure = (context) =>
                {
                    context.Response.Redirect("/Account/AccessDenied");
                    context.HandleResponse();
                    return Task.CompletedTask;
                },

                OnSignedOutCallbackRedirect = context =>
                {
                    context.HttpContext.Response.Cookies?.Delete(_configuration["Properties:SharedAntiForgCookie"]);
                    return Task.CompletedTask;
                },

                OnRedirectToIdentityProvider = context =>
                {
                    context.ProtocolMessage.Prompt = OidcConstants.PromptModes.None;
                    return Task.CompletedTask;
                }
            };

        }
    }
}
