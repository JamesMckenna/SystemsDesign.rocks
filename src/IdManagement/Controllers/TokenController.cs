using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;

using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using Serilog;

namespace IdManagement.Controllers
{
    public class TokenController : Controller
    {
        /****************** Something to remember about IS4 tokens ************************/

        //var user_access_token = await HttpContext.GetUserAccessTokenAsync();

        //var client_app_access_token = await HttpContext.GetClientAccessTokenAsync();

        /****************** Tokens can be accessed using the HTTPContext ******************/

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IDiagnosticContext _diagnosticContext;
        public TokenController(IHttpClientFactory httpClientFactory, IDiagnosticContext diagnosticContext)
        {
            _httpClientFactory = httpClientFactory;
            _diagnosticContext = diagnosticContext;
        }

        public async Task<string> GetAccessToken()
        {
            string accessToken = await HttpContext.GetTokenAsync("access_token");

            if (String.IsNullOrEmpty(accessToken)) throw new Exception("No Access Token found");

            _diagnosticContext.Set("Token/GetAccessToken", 1423);
            return accessToken;
        }

        public async Task<IActionResult> AccessToken()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(AppConfig.ID_API_BASE_URL + "/");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            string content = await client.GetStringAsync("token");

            if (String.IsNullOrEmpty(content)) throw new Exception("Unable to reach Identity Api");

            ViewBag.Msg = "Access Token";
            ViewBag.Token = JArray.Parse(content).ToString();

            _diagnosticContext.Set("Token/AccessToken", 1423);
            return View("Token");
        }

        public async Task<IActionResult> DiscoveryDocument()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = AppConfig.IS4_BASE_URL,
                Policy = {
                    AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                    ValidateEndpoints = true,
                    ValidateIssuerName = true
                }
            });

            if (disco.IsError) throw new Exception(disco.Error);

            ViewBag.Msg = "Discovery Document";
            ViewBag.Token = disco.Json;

            _diagnosticContext.Set("Token/DiscoveryDocument", 1423);
            return View("Token");
        }

        public async Task<IActionResult> TokenIntrospectionEndpoint()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("token", accessToken);

            TokenIntrospectionResponse response = await client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = AppConfig.IS4_BASE_URL + "/connect/introspect",
                ClientId = AppConfig.ID_API,
                ClientSecret = AppConfig.ID_API_SECRET,
                Token = accessToken
            });

            if (response.IsError) throw new Exception(response.Error);

            ViewBag.Msg = "Token Introspection Endpoint";
            ViewBag.Token = response.Json;

            _diagnosticContext.Set("Token/TokenIntrospectionEndpoint", 1423);
            return View("Token");
        }

        public async Task<IActionResult> UserInfoEndpoint()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();

            UserInfoResponse response = await client.GetUserInfoAsync(new UserInfoRequest
            {
                Address = await GetUserInfoEndpointAsync(),
                Token = accessToken
            });

            if (response.IsError) throw new Exception(response.Error);

            ViewBag.Token = response.Json;
            ViewBag.Msg = "UserInfo Endpoint - Claims";

            _diagnosticContext.Set("Token/UserInfoEndpoint", 1423);
            return View("Token");
        }

        public async Task<IActionResult> TokenRevocationEndpoint()
        {
            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient();

            TokenRevocationResponse response = await client.RevokeTokenAsync(new TokenRevocationRequest
            {
                Address = await GetRevocationEndpointAsync(),
                ClientId = AppConfig.CLIENT_ID,
                ClientSecret = AppConfig.CLIENT_SECRET,
                Token = accessToken,
                TokenTypeHint = "access_token"
            });

            if (response.IsError) throw new Exception(response.Error);

            _diagnosticContext.Set("Token/TokenRevocationEndpoint", 1423);
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> CallApiAsUser()
        {
            HttpClient client = _httpClientFactory.CreateClient("user_client");

            string response = await client.GetStringAsync("token");

            if (String.IsNullOrEmpty(response)) throw new Exception("Unable to Call Api as User");

            ViewBag.Token = JArray.Parse(response).ToString();
            ViewBag.Msg = "Call Api as User";

            _diagnosticContext.Set("Token/CallApiAsUser", 1423);
            return View("Token");
        }

        public async Task<IActionResult> CallApiAsClient()
        {
            HttpClient client = _httpClientFactory.CreateClient(AppConfig.CLIENT_ID);

            string response = await client.GetStringAsync("token");

            if (String.IsNullOrEmpty(response)) throw new Exception("Unable to Call Api as Client App");

            ViewBag.Token = JArray.Parse(response).ToString();
            ViewBag.Msg = "Call Api as Client App";

            _diagnosticContext.Set("Token/CallApiAsClient", 1423);
            return View("Token");
        }


        /*****************   Start Get Endpoints Actions     ***************************/
        public async Task<string> GetUserInfoEndpointAsync()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = AppConfig.IS4_BASE_URL,
                Policy = {
                    AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                    ValidateEndpoints = true,
                    ValidateIssuerName = true
                }
            });

            if (disco.IsError) throw new Exception(disco.Error);

            _diagnosticContext.Set("Token/GetUserInfoEndpointAsync", 1423);
            return disco.UserInfoEndpoint;
        }

        public async Task<string> GetIntrospectionEndpointAsync()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = AppConfig.IS4_BASE_URL,
                Policy = {
                    AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                    ValidateEndpoints = true,
                    ValidateIssuerName = true
                }
            });

            if (disco.IsError) throw new Exception(disco.Error);

            _diagnosticContext.Set("Token/GetIntrospectionEndpointAsync", 1423);
            return disco.IntrospectionEndpoint;
        }

        public async Task<string> GetRevocationEndpointAsync()
        {
            HttpClient client = _httpClientFactory.CreateClient();

            DiscoveryDocumentResponse disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = AppConfig.IS4_BASE_URL,
                Policy = {
                    AuthorityValidationStrategy = new AuthorityUrlValidationStrategy(),
                    ValidateEndpoints = true,
                    ValidateIssuerName = true
                }
            });

            if (disco.IsError) throw new Exception(disco.Error);

            _diagnosticContext.Set("Token/GetRevocationEndpointAsync", 1423);
            return disco.RevocationEndpoint;
        }
    }
}