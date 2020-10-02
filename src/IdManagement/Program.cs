using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Extensions.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace IdManagement
{
    public class Program
    {
        static readonly LoggerProviderCollection Providers = new LoggerProviderCollection();
        public static int Main(string[] args)
        {
            Activity.DefaultIdFormat = ActivityIdFormat.W3C;
            //var name = Assembly.GetExecutingAssembly().GetName();
            //Log.Logger = new LoggerConfiguration()
            //.MinimumLevel.Debug()
            //.MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            //.MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            //.MinimumLevel.Override("Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware", LogEventLevel.Fatal)//Prevents multiple log entries for the same error
            //.Enrich.FromLogContext()
            //.Enrich.WithProperty("Assembly", $"{name.Name}")
            //.Filter.ByExcluding("RequestPath = '/lib/*' and StatusCode = 200")
            //.Filter.ByExcluding("RequestPath = '/js' and StatusCode = 200")
            //.Filter.ByExcluding("RequestPath = '/css' and StatusCode = 200")
            //.WriteTo.Console()
            //.WriteTo.Providers(Providers)
            //.WriteTo.File("..\\Logs\\IdManagement\\IdManagement.log", LogEventLevel.Information, 
            //            outputTemplate: "\n{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Properties}{NewLine}{Exception}", 
            //            null, 1073741824, null, true, false, TimeSpan.FromSeconds(1), RollingInterval.Day, true, 31, null, null)
            //.CreateLogger();

            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", false, true)
                .Build();

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .CreateLogger();

            Log.Information("Logging from Id Management Program.cs - Id Management starting up");

            try
            {

                var seed = args.Contains("/seed");
                //var seed = true;
                if (seed)
                {
                    args = args.Except(new[] { "/seed" }).ToArray();
                }

                var host = CreateHostBuilder(args).Build();

                if (seed)
                {
                    Log.Information("Seeding database...");
                    var config = host.Services.GetRequiredService<IConfiguration>();
                    var connectionString = config.GetConnectionString("DefaultConnection");
                    SeedData.EnsureSeedData(connectionString);
                    Log.Information("Done seeding database.");
                    return 0;
                }

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
                .ConfigureAppConfiguration((hostContext, config) => 
                {
                    var secretsPath = Environment.GetEnvironmentVariable("SECRETS_PATH");
                    var env = hostContext.HostingEnvironment;
                    config.AddJsonFile(secretsPath, false, true);
  
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
