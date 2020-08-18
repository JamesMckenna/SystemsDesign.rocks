using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace IdManagement.Services.HealthCheck
{
    public class IdApiHealthCheck : IHealthCheck
    {
        public string Name = "IdApiHealthCheck";
        private string _httpClientName;
        private string _action;
        private IHttpClientFactory _httpClientFactory;

        public IdApiHealthCheck(IHttpClientFactory httpClientFactory, string httpClientName, string action)
        {
            //A named http client initialized in the Startup.Configure method. 
            //services.AddClientAccessTokenClient is an Identity Model extension method that uses IHttpClientFactory to create a httpclient,
            //retrieve an access token and apply it to the named httpclient's, authoization header. We use that named httpclient (and access token) here to make a request to the IdApi 
            _httpClientName = httpClientName;
            //The controller and action method to execute at the Api
            _action = action;
            _httpClientFactory = httpClientFactory;
        }

        async Task<HealthCheckResult> IHealthCheck.CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken)
        {
            HttpClient client = _httpClientFactory.CreateClient(_httpClientName);

            string response = await client.GetStringAsync(_action);

            return (response == "Healthy") ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy();          
        }
    }
}
