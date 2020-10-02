using IdentityCommon;
using IdManagement.Services.DataProtectionServices;
using Microsoft.AspNetCore.Identity;

namespace IdManagement.AppConfiguration
{
    internal static class AppIdentityOptions
    {
        internal static void App_Identity_Options(IdentityOptions options)
        {
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequiredLength = 6;
            options.Password.RequiredUniqueChars = 1;

            options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._+";
            options.User.RequireUniqueEmail = true;

            //Tokens sent for ForgotPassword & ConfirmRegister will expire 4 hours after sending email to user
            options.Tokens.ProviderMap.Add("CustomEmailConfirmation", new TokenProviderDescriptor(typeof(CustomEmailConfirmationTokenProvider<ApplicationUser>)));
            options.Tokens.EmailConfirmationTokenProvider = "CustomEmailConfirmation";
        }
    }
}
