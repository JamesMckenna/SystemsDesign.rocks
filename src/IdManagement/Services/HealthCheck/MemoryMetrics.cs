using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdManagement.Services.HealthCheck
{
    //https: //dzone.com/articles/system-memory-health-check-for-aspnet-core
    public class MemoryMetrics
    {
        public double Total;
        public double Used;
        public double Free;
        public long CheckDurationInMilliseconds;
    }
}
