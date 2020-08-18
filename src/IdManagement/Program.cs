using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Extensions.Logging;

namespace IdManagement
{
    public class Program
    {
        static readonly LoggerProviderCollection Providers = new LoggerProviderCollection();
        public static int Main(string[] args)
        {
            Activity.DefaultIdFormat = ActivityIdFormat.W3C;

            Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Filter.ByExcluding("RequestPath = '/lib/*' and StatusCode = 200")
            .Filter.ByExcluding("RequestPath = '/js' and StatusCode = 200")
            .Filter.ByExcluding("RequestPath = '/css' and StatusCode = 200")
            .WriteTo.Console()
            .WriteTo.Providers(Providers)
            .WriteTo.File("..\\Logs\\IdManagement\\IdManagement.log", LogEventLevel.Information, 
                        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}", 
                        null, 1073741824, null, true, false, TimeSpan.FromSeconds(1), RollingInterval.Day, true, 31, null, null)
            .CreateLogger();

            Log.Information("Logging from Id Management Program.cs - Id Management starting up");

            try
            {
                Log.Information("Starting host...");
                CreateHostBuilder(args).Build().Run();
                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly.");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilog(providers: Providers)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
