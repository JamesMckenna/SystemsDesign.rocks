using IdentityModel.AspNetCore.AccessTokenManagement;
using Microsoft.Extensions.Configuration;
using System;

namespace IdManagement.AppConfiguration
{
    internal static class AppIdentityModelTokenManagement
    {
        private static IConfiguration _configuration;

        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        internal static void TokenManagementOptions(AccessTokenManagementOptions options)
        {
            string clientId = _configuration["ApplicationIds:IdManagementId"];

            options.Client.Clients.Add(clientId, new IdentityModel.Client.ClientCredentialsTokenRequest
            {
                Address = _configuration["AppURLS:IS4BaseUrl"] + "/connect/token",
                ClientId = clientId,
                ClientSecret = _configuration["ApplicationSecrets:IdManagementSecret"],
                Scope = _configuration["ApplicationIds:IdApiId"]
            });

            options.Client.Scope = _configuration["ApplicationIds:IdApiId"];
        }
    }
}
