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
        private static double tokenExpireSeconds;
        private static double authCookieExpireSeconds;
        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
            tokenExpireSeconds = Double.Parse(_configuration["LifeTimes:TokenExpireSeconds"].ToString());
            authCookieExpireSeconds = Double.Parse(_configuration["LifeTimes:AuthCookieExpireSeconds"].ToString());
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
                    ClientName = _configuration["ApplicationNames:IdentityManagementName"],
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
                        _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/PasswordChanged",
                        _configuration["AppURLS:IdManagementBaseUrl"] + "/Manage/ResetPasswordConfirmation"
                    },

                    AllowedCorsOrigins = new string[] {
                        _configuration["AppURLS:IdManagementBaseUrl"],
                        _configuration["AppURLS:MainClientBaseUrl"]
                    },

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "IdApi", "offline_access"
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    RequireConsent = false,
                    
                    FrontChannelLogoutSessionRequired = true,
                    FrontChannelLogoutUri = _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/FrontChannelLogout",

                    BackChannelLogoutSessionRequired = true,
                    BackChannelLogoutUri = _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/BackChannelLogout",

                    //Token Management
                    //User Info not in Id_token unless asked using UserInfo EndPoint
                    //Better than JWT, Reference tokens can be revoked using Token Revocation Endpoint but means more back channel traffic between Api, Clients and IS4
                    AccessTokenType = AccessTokenType.Reference, 
                    AllowOfflineAccess = true, //enables support for refresh tokens
                    AbsoluteRefreshTokenLifetime = 36000,

                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration= TokenExpiration.Sliding,
                    SlidingRefreshTokenLifetime = (int)tokenExpireSeconds,

                    UpdateAccessTokenClaimsOnRefresh = true,
                    UserSsoLifetime = (int)authCookieExpireSeconds,

                    IdentityTokenLifetime = (int)tokenExpireSeconds,
                    AccessTokenLifetime = (int)tokenExpireSeconds,
                    AuthorizationCodeLifetime = (int)authCookieExpireSeconds,
                },


                 new Client
                 {
                    ClientId = _configuration["ApplicationIds:MainClient"],
                    ClientName = _configuration["ApplicationNames:MainClient"],

                    RequireClientSecret = false,

                    AllowedGrantTypes = {
                        GrantType.AuthorizationCode,
                        GrantType.ClientCredentials
                    },

                    RedirectUris = new string[] { 
                        _configuration["AppURLS:MainClientBaseUrl"] + "/callback.html",
                        _configuration["AppURLS:MainClientBaseUrl"] + "/silent-refresh.html",
                        _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/*"
                    },

                    PostLogoutRedirectUris = new string[] {
                        _configuration["AppURLS:MainClientBaseUrl"]
                    },

                    AllowedCorsOrigins = new string[] {
                        _configuration["AppURLS:IdManagementBaseUrl"],
                        _configuration["AppURLS:IS4BaseUrl"],
                        _configuration["AppURLS:MainClientBaseUrl"]
                    },

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "offline_access", "IdApi"
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    RequireConsent = true,

                    AlwaysIncludeUserClaimsInIdToken = true,

                    //AllowAccessTokensViaBrowser = true,
                    //The refresh token should be long lived (at least longer than the access token).
                    //Once the refresh token expires, the user has to login again. Without sliding expiration the refresh token will expire in an absolute time, having the user to login again.
                    //https://stackoverflow.com/questions/50363450/identityserver4-access-token-lifetime/50364604
                    AccessTokenType = AccessTokenType.Reference,
                    AllowOfflineAccess = true, //Allows Refresh Token
                    
                    //Token lifetime - NOT COOKIE LIFETIME, NOT AUTHENTICATION LIFETIME. Just how long an access token can be used against an API (Resource registered with IS4) 
                    IdentityTokenLifetime = (int)tokenExpireSeconds, //Default 300 seconds
                    AccessTokenLifetime = (int)tokenExpireSeconds, //Default 3600 seconds, 1 hour
                    AuthorizationCodeLifetime = (int)authCookieExpireSeconds, //Default 300 seconds: Once User consents, this token should no longer be needed until re-authorization. This AuthorizationCode is used to prove to IS4 that an access token and id token have been constented too and from there the refresh token takes over. So if using refresh tokens, AuthorizationCode shouldn't need a long lifetime. 
                    
                    AbsoluteRefreshTokenLifetime = 36000, //Defaults to 2592000 seconds / 30 days - NOT GOOD FOR SPA's - 36000 = 10 hours
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration = TokenExpiration.Sliding,
                    SlidingRefreshTokenLifetime = (int)tokenExpireSeconds,//token will be refreshed only if this value has 50% elasped. Router Guard on Vue Router will ask for refresh on every page navigation. If 50% elapsed, refresh will happen. Setting the accessTokenExpiringNotificationTime of the oidc-client to the same timeout, will allow refresh on page navigation (assuming access and id tokens haven't already expired)
                    UpdateAccessTokenClaimsOnRefresh = true, //Gets or sets a value indicating whether the access token (and its claims) should be updated on a refresh token request.
                                       
                     UserSsoLifetime = (int)authCookieExpireSeconds,
                    /* The maximum duration (in seconds) since the last time the user authenticated. 
                     * Defaults to null. 
                     * You can adjust the lifetime of a session token to control when and how often a user is required to reenter credentials
                     * instead of being silently authenticated, when using a web application.*/


                 }
            };
    }
}