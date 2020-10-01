using Microsoft.AspNetCore.Authentication;

namespace IdManagement.AppConfiguration
{
    internal static class AppAuthenticationOptions
    {
        internal static void AuthOptions(AuthenticationOptions options)    
        {
            options.DefaultScheme = "Cookies";
            options.DefaultChallengeScheme = "oidc";
            options.DefaultSignOutScheme = "Cookies";
        }  
    }
}
