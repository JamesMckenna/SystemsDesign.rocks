using IdManagement.Services.Logging;
using Microsoft.AspNetCore.Mvc;

namespace IdManagement.AppConfiguration
{
    internal static class AppMvcOptions
    {
        internal static void MVCControllerOptions(MvcOptions options)
        {
            options.Filters.Add<LoggingActionFilter>();
        }
    }
}
