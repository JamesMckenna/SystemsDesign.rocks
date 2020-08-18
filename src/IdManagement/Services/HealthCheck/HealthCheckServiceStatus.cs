using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdManagement.Services.HealthCheck
{
    public class HealthCheckServiceStatus
    {
        public string Service { get; set; }
        public int StatusNumber { get; set; }
        public string Status { get; set; }
        public List<KeyValuePair<string, object>> Data {get; set;}
    }
}
