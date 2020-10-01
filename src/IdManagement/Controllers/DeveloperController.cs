using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace IdManagement.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class DeveloperController : Controller
    {
        /****************** Something to remember about IS4 tokens ************************/

        //public async Task GetProfileDataAsync(ProfileDataRequestContext context)

        //var user_access_token = await HttpContext.GetUserAccessTokenAsync();

        //var client_app_access_token = await HttpContext.GetClientAccessTokenAsync();

        /****************** Tokens can be accessed using the HTTPContext ******************/

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<DeveloperController> _logger;
        private IDataProtectionProvider _protectionProvider;
        public DeveloperController(IHttpClientFactory httpClientFactory, 
            IConfiguration configuration, 
            ILogger<DeveloperController> logger,
            IDataProtectionProvider protectionProvider)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _logger = logger;
            _protectionProvider = protectionProvider;
        }

        public IActionResult Index()
        {
            return View();
        }

        #region Helper method for rest of controller actions
        private async Task<string> GetAccessToken()
        {
            string accessToken = await HttpContext.GetTokenAsync("access_token");
            if (String.IsNullOrEmpty(accessToken)) 
            {
                _logger.LogError("~/Developer/GetAccessToken - Access token could not be retieved.");
                throw new NullReferenceException("No Access Token found"); 
            }

            return accessToken;
        }
        #endregion

        #region Show Access Token
        [HttpGet]
        public async Task<IActionResult> AccessToken()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(_configuration["AppURLS:IdApiBaseUrl"] + "/");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            string content;
            try
            {
                content = await client.GetStringAsync("token");
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/AccessToken - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["Message"]= "Access Token";
            TempData["Token"] = JArray.Parse(content)?.ToString();

            return View("Developer");
        }
        #endregion

        #region Show Discovery Document
        [HttpGet]
        [Route("/Token/DiscoveryDocument")]
        public async Task<IActionResult> DiscoveryDocument()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco;
            try 
            {
                disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                    {
                        Address = _configuration["AppURLS:IS4BaseUrl"],
                        Policy = {
                        AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                        ValidateEndpoints = true,
                        ValidateIssuerName = true
                    }
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/DiscoveryDocument - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["Message"] = "Discovery Document";
            TempData["Token"] = disco?.Json.ToString();

            return View("Developer");
        }
        #endregion

        #region How to use IS4 Endpoints
        [HttpGet]
        public async Task<IActionResult> TokenIntrospectionEndpoint()
        {
            string accessToken = await GetAccessToken();


            HttpClient client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("token", accessToken);

            TokenIntrospectionResponse response;
            try
            {
                response = await client.IntrospectTokenAsync(new TokenIntrospectionRequest
                {
                    Address = _configuration["AppURLS:IS4BaseUrl"] + "/connect/introspect",
                    ClientId = _configuration["ApplicationIds:IdApiId"],
                    ClientSecret = _configuration["ApplicationSecrets:IdApiSecret"],
                    Token = accessToken
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/TokenIntrospectionEndpoint - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["Message"] = "Token Introspection Endpoint";
            TempData["Token"] = response?.Json.ToString();

            return View("Developer");
        }

        [HttpGet]
        public async Task<IActionResult> UserInfoEndpoint()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();

            UserInfoResponse response;
            try
            {
                response = await client.GetUserInfoAsync(new UserInfoRequest
                {
                    Address = await GetUserInfoEndpointAsync(),
                    Token = accessToken
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/UserInfoEndpoint - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["Message"] = "UserInfo Endpoint - Claims";
            TempData["Token"] = response.Json.ToString();

            return View("Developer");
        }

        [HttpGet]
        public async Task<IActionResult> TokenRevocationEndpoint()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();

            TokenRevocationResponse response;
            try
            {
                response = await client.RevokeTokenAsync(new TokenRevocationRequest
                {
                    Address = await GetRevocationEndpointAsync(),
                    ClientId = _configuration["ApplicationIds:IdManagementId"],
                    ClientSecret = _configuration["ApplicationSecrets:IdManagementSecret"],
                    Token = accessToken,
                    TokenTypeHint = "access_token"
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/TokenRevocationEndpoint - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["StatusMessage"] = "User access token has been revoked. User will have to log back in to access Api resources. To be concise, this endpoint revokes the refresh token. So the access token WILL NOT be refreshed - thus the User will not be able to access Api resources once the current access token expires.";
            return RedirectToAction("Index", "Home");
        }
        #endregion

        #region AccessTokenManagement from Identity Model - Registered in StartUp.cs
        [HttpGet]
        public async Task<IActionResult> CallApiAsUser()
        {
            HttpClient client = _httpClientFactory.CreateClient("user_client");

            string response;
            try
            {
                response = await client.GetStringAsync("token");
            }
            catch(HttpRequestException ex)
            {
                _logger.LogError("~/Developer/CallApiAsUser - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["Message"] = "Call Api as User";
            TempData["Token"] = JArray.Parse(response).ToString();
            
            return View("Developer");
        }

        [HttpGet]
        public async Task<IActionResult> CallApiAsClient()
        {
            HttpClient client = _httpClientFactory.CreateClient(_configuration["ApplicationIds:IdManagementId"]);

            string response;
            try
            {
                response = await client.GetStringAsync("token");
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/CallApiAsClient - An error occurred getting data from the IdApi App: {0}", ex);
                throw;
            }

            TempData["Message"] = "Call Api as User";
            TempData["Token"] = JArray.Parse(response).ToString();

            return View("Developer");
        }
        #endregion

        #region Get End Points from Discovery Document - Discovery Document can be cache but currenlty is not cached in this app.
        /*****************   Start Get Endpoints Actions     ***************************/
        private async Task<string> GetUserInfoEndpointAsync()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco;
            try
            {
                disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                {
                    Address = _configuration["AppURLS:IS4BaseUrl"],
                    Policy = {
                        AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                        ValidateEndpoints = true,
                        ValidateIssuerName = true
                    }
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/GetUserInfoEndpointAsync - An error occurred getting User Info Endpoint from Discovery Document: {0}", ex);
                throw;
            }

            return disco.UserInfoEndpoint;
        }

        private async Task<string> GetRevocationEndpointAsync()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco;
            try
            {
                disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                {
                    Address = _configuration["AppURLS:IS4BaseUrl"],
                    Policy = {
                        AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                        ValidateEndpoints = true,
                        ValidateIssuerName = true
                    }
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/GetIntrospectionEndpointAsync - An error occurred getting Revocation Endpoint from Discovery Document: {0}", ex);
                throw;
            }

            return disco.RevocationEndpoint;
        }
        #endregion

        //Introspection is typically used by APIs to validate an incoming token.
        //This method shows how to get the Introspection Endpoint from the Discovery Document; not how to use it.
        private async Task<string> GetIntrospectionEndpointAsync()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco;
            try
            {
                disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                {
                    Address = _configuration["AppURLS:IS4BaseUrl"],
                    Policy = {
                        AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                        ValidateEndpoints = true,
                        ValidateIssuerName = true
                    }
                });
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Developer/GetIntrospectionEndpointAsync - An error occurred getting Introspection Endpoint from Discovery Document: {0}", ex);
                throw;
            }

            return disco.IntrospectionEndpoint;
        }
    }
}