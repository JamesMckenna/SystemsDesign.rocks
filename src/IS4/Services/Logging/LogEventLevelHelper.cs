using Microsoft.AspNetCore.Http;
using Serilog.Events;
using System;

namespace IS4.Services.Logging
{
    public static class LogEventLevelHelper
    {
        //FROM Andrew Lock Blog about Serilog
        private static bool IsHealthCheckEndpoint(HttpContext context)
        {
            var endpoint = context.GetEndpoint();
            if (endpoint is object) // same as !(endpoint is null)
            {
                return string.Equals(
                    endpoint.DisplayName,
                    "Health checks",
                    StringComparison.Ordinal);
            }
            // No endpoint, so not a health check endpoint
            return false;
        }

        public static LogEventLevel CustomGetLevel(HttpContext context, double _, Exception ex) =>
           ex != null
               ? LogEventLevel.Error
               : context.Response.StatusCode > 499
                   ? LogEventLevel.Error
                   : IsHealthCheckEndpoint(context) // Not an error, check if it was a health check
                        ? LogEventLevel.Verbose // Was a health check, use Verbose
                        : LogEventLevel.Information;
    }
}

