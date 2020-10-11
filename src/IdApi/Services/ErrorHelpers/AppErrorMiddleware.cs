using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace IdApi.Services.ErrorHelpers
{
    public class AppErrorMiddleware
    {

        private readonly RequestDelegate _next;
        private readonly ILogger<AppErrorMiddleware> _logger;

        public AppErrorMiddleware(RequestDelegate next, ILogger<AppErrorMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next.Invoke(context);
            }
            catch (Exception ex)
            {
                //Logs all unhandled exceptions
                _logger.LogError(ex, ex.Message);
                context.Response.StatusCode = 500;
            }

            //Create homongenious error response, whether statuscode 4xx or exception (statuscode > 499)
            if (!context.Response.HasStarted)
            {
                context.Response.ContentType = "application/json";
                ApiResponse response = new ApiResponse(context.Response.StatusCode);
                string jsonResponse = JsonSerializer.Serialize(response);
                await context.Response.WriteAsync(jsonResponse);
            }
        }
    }
}
   
