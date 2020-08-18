// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace IS4
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("IdApi", "Identity Api"),
            };

        public static IEnumerable<ApiResource> ApiResources =>
            new List<ApiResource>
            {
                new ApiResource("IdApi", "Identity Api")
                {
                    ApiSecrets = { new Secret("secret".Sha256())},
                    Scopes = {"IdApi"}
                }
            };

        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                new Client
                {
                    ClientId = "IdManagement",
                    ClientName = "Identity Management",
                    ClientSecrets = { new Secret("secret".Sha256())},
                    AllowedGrantTypes = {
                        GrantType.AuthorizationCode,
                        GrantType.ClientCredentials
                    },

                    RedirectUris = { "https://localhost:5002/signin-oidc"},
                    PostLogoutRedirectUris = {"https://localhost:5002/signout-callback-oidc"},
                    AllowedCorsOrigins = {"https://localhost:5002"},
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "IdApi",
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    RequireConsent = true,

                    //Token Management
                    //AlwaysIncludeUserClaimsInIdToken = true,
                    AccessTokenType = AccessTokenType.Reference, //Better than JWT, Reference tokens can be revoked using Token Revocation Endpoint but means more back channel traffic between Api and IS4
                    AllowOfflineAccess = true, //enables support for refresh tokens
                    AbsoluteRefreshTokenLifetime = 0,
                    RefreshTokenExpiration= TokenExpiration.Sliding,
                    SlidingRefreshTokenLifetime = 300,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    UpdateAccessTokenClaimsOnRefresh = true
                }
            };
    }
}