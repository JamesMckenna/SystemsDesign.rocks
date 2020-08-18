using Microsoft.Extensions.Diagnostics.HealthChecks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IdManagement.Services.HealthCheck
{
    //https: //dzone.com/articles/system-memory-health-check-for-aspnet-core
    public class SystemMemoryHealthCheck : IHealthCheck
    {
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken)
        {
            MemoryMetricsClient client = new MemoryMetricsClient();
            MemoryMetrics metrics = client.GetMetrics();
            double percentUsed = 100 * metrics.Used / metrics.Total;
            HealthStatus status = HealthStatus.Healthy;

            if (percentUsed > 80)
            {
                status = HealthStatus.Degraded;
            }

            if (percentUsed > 90)
            {
                status = HealthStatus.Unhealthy;
            }

            Dictionary<string, object> data = new Dictionary<string, object>
            {
                { "Total", metrics.Total },
                { "Used", metrics.Used },
                { "Free", metrics.Free },
                { "CheckDurationInMilliseconds", metrics.CheckDurationInMilliseconds }
        };

            HealthCheckResult result = new HealthCheckResult(status, null, null, data);

            return await Task.FromResult(result);
        }
    }
}
