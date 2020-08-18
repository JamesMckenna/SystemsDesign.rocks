using IdentityModel.AspNetCore.AccessTokenManagement;
using IdManagement.Services.Logging;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace IdManagement
{
    internal static class AppConfig
    {
        internal const string COOKIE = "Cookies";
        internal const string OIDC = "oidc";

        internal const string ID_API = "IdApi";
        internal static string ID_API_SECRET { get; private set; } = "secret";
        internal const string ID_API_BASE_URL = "https://localhost:6001";

        internal const string CLIENT_ID = "IdManagement";
        internal static string CLIENT_SECRET { get; private set; } = "secret";
        internal const string IS4_BASE_URL = "https://localhost:5001";

        internal static void AuthOptions(AuthenticationOptions options)
        {
            options.DefaultScheme = COOKIE;
            options.DefaultChallengeScheme = OIDC;
            options.DefaultSignOutScheme = COOKIE;
        }

        public static void CookieOptions(CookieAuthenticationOptions options)
        {
            options.Cookie.Name = CLIENT_ID + "Cookie";
            options.Events.OnSigningOut = async e => await e.HttpContext.RevokeUserRefreshTokenAsync();
        }

        public static void OidcOptions(OpenIdConnectOptions options)
        {
            options.Authority = IS4_BASE_URL;
            options.ClientId = CLIENT_ID;
            options.ClientSecret = CLIENT_SECRET;
            options.ResponseType = "code";
            options.UsePkce = true;
            options.ResponseMode = "query";
            options.Scope.Add(ID_API);
            options.Scope.Add("offline_access");

            options.ClaimActions.MapJsonKey("website", "website");

            options.GetClaimsFromUserInfoEndpoint = true;//keeps id_token smaller
            options.SaveTokens = true;

            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = "role"
            };
        }

        //FROM IdentityModel
        public static void AccessTokenManagment(AccessTokenManagementOptions options)
        {
            options.Client.Clients.Add(CLIENT_ID, new IdentityModel.Client.ClientCredentialsTokenRequest
            {
                Address = IS4_BASE_URL + "/connect/token",
                ClientId = CLIENT_ID,
                ClientSecret = CLIENT_SECRET,
                Scope = ID_API
            });

            options.Client.Scope = ID_API;
        }

        public static void MVCControllerOptions(MvcOptions options)
        {
            options.Filters.Add<LoggingActionFilter>();
            //https: //docs.microsoft.com/en-us/archive/msdn-magazine/2016/august/asp-net-core-real-world-asp-net-core-mvc-filters
            //https: //docs.microsoft.com/en-us/aspnet/core/mvc/controllers/filters?view=aspnetcore-3.1
        }
    }
}
