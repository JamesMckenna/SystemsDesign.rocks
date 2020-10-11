using Microsoft.Extensions.Configuration;
using Swashbuckle.AspNetCore.Swagger;

namespace IdApi.AppConfiguration
{
    internal static class SwaggerOps
    {
        private static IConfiguration _configuration;

        internal static void SetDI(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public static void GetSwaggerOps(SwaggerOptions options)
        {
            options.RouteTemplate = _configuration["SwaggerOptions:JsonRoute"];
        }
    }
}
