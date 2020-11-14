using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Extensions.Logging;
using System;
using System.IO;
using System.Linq;
namespace IdApi
{
    public class Program
    {
        static readonly LoggerProviderCollection Providers = new LoggerProviderCollection();
        public static int Main(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", false, true)
                .Build();

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .CreateLogger();

            Log.Information("Logging from IdApi Program.cs - IdApi starting up");

            try
            {
                var host = CreateHostBuilder(args).Build();

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
                    var configuration = config.Build();

                    //Leave this in for now
                    //SeedDB(configuration);
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });

        private static void SeedDB(IConfiguration configuration)
        {
            Log.Information("Seeding database...");
            var connectionString = configuration["IdApiConnectionStrings:IdentityDB"];
            SeedData.EnsureSeedData(connectionString);
            Log.Information("Done seeding database.");
        }
    }
}
