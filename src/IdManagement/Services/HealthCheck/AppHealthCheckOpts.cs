using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;

namespace IdManagement.Services.HealthCheck
{
    public class AppHealthCheckOpts
    {
        public static HealthCheckOptions HealthCheckOpts()
        {
            HealthCheckOptions options = new HealthCheckOptions();
            var json = "";
            options.AllowCachingResponses = false;
            options.ResponseWriter = async (context, report) =>
            {
                context.Response.ContentType = "application/json";
                List<HealthCheckServiceStatus> result = new List<HealthCheckServiceStatus>();
                result.Add(new HealthCheckServiceStatus { Service = "OverAll", StatusNumber = (int)report.Status, Status = report.Status.ToString() });
                result.AddRange(
                      report.Entries.Select(
                        e => new HealthCheckServiceStatus
                        {
                            Service = e.Key,
                            StatusNumber = (int)e.Value.Status,
                            Status = report.Status.ToString(),
                            Data = e.Value.Data.Select(k => k).ToList(),
                        }
                      ));

                json = JsonConvert.SerializeObject(result);

                await context.Response.WriteAsync(json);
            };

            return options;
        }
    }
}
