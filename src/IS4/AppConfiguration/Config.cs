using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;

namespace IS4.AppConfiguration
{
    internal static class Config
    {

        private static IConfiguration _configuration;
        private static double expireSeconds;
        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
            expireSeconds = Double.Parse(_configuration["CookieExpireSeconds"].ToString());
        }

        internal static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
            };

        internal static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope( _configuration["ApplicationIds:IdApiId"], _configuration["ApplicationNames:IdApiName"]),
            };

        internal static IEnumerable<ApiResource> ApiResources =>
            new List<ApiResource>
            {
                new ApiResource(_configuration["ApplicationIds:IdApiId"], _configuration["ApplicationNames:IdApiName"])
                {
                    ApiSecrets = { 
                        new Secret(_configuration["ApplicationSecrets:IdApiSecret"].Sha256())
                    },

                    Scopes = {
                        _configuration["ApplicationIds:IdApiId"]
                    }
                }
            };

        internal static IEnumerable<Client> Clients =>
            new List<Client>
            {
                new Client
                {
                    ClientId = _configuration["ApplicationIds:IdManagementId"],
                    ClientName = _configuration["ApplicationNames:Identity Management"],
                    ClientSecrets = {
                        new Secret(_configuration["ApplicationSecrets:IdManagementSecret"].Sha256())
                    },

                    AllowedGrantTypes = {
                        GrantType.AuthorizationCode,
                        GrantType.ClientCredentials
                    },

                    RedirectUris = { _configuration["AppURLS:IdManagementBaseUrl"] + "/signin-oidc" },

                    PostLogoutRedirectUris = new string[] {
                        _configuration["AppURLS:IdManagementBaseUrl"] + "/signout-callback-oidc",
                        _configuration["AppURLS:IdManagementBaseUrl"] + "/Manage/ResetPasswordConfirmation"
                    },

                    AllowedCorsOrigins = new string[] {
                        _configuration["AppURLS:IdManagementBaseUrl"]
                    },

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "IdApi",
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    RequireConsent = true,
                    
                    FrontChannelLogoutSessionRequired = true,
                    FrontChannelLogoutUri = _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/FrontChannelLogout",

                    BackChannelLogoutSessionRequired = true,
                    BackChannelLogoutUri = _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/BackChannelLogout",

                    //Token Management
                    //User Info not in Id_token unless asked using UserInfo EndPoint
                    //Better than JWT, Reference tokens can be revoked using Token Revocation Endpoint but means more back channel traffic between Api, Clients and IS4
                    AccessTokenType = AccessTokenType.Reference, 
                    AllowOfflineAccess = true, //enables support for refresh tokens
                    AbsoluteRefreshTokenLifetime = 0,
                    

                    SlidingRefreshTokenLifetime = (int)expireSeconds,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration= TokenExpiration.Sliding,

                    UpdateAccessTokenClaimsOnRefresh = true,
                    UserSsoLifetime = (int)expireSeconds,

                    IdentityTokenLifetime = (int)expireSeconds,
                    AccessTokenLifetime = (int)expireSeconds,
                    AuthorizationCodeLifetime = (int)expireSeconds,
                }
            };
    }
}