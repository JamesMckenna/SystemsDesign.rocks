// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


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

namespace IS4
{
    public class Program
    {
        static readonly LoggerProviderCollection Providers = new LoggerProviderCollection();
        public static int Main(string[] args)
        {
            Activity.DefaultIdFormat = ActivityIdFormat.W3C;

            //Log.Logger = new LoggerConfiguration()
            //.MinimumLevel.Debug()
            //.MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            //.MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            //.MinimumLevel.Override("Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware", LogEventLevel.Fatal)
            //.Enrich.FromLogContext()
            //.Filter.ByExcluding("RequestPath = '/lib/*' and StatusCode = 200")
            //.Filter.ByExcluding("RequestPath = '/js' and StatusCode = 200")
            //.Filter.ByExcluding("RequestPath = '/css' and StatusCode = 200")
            //.WriteTo.Console()
            //.WriteTo.Providers(Providers)
            //.WriteTo.File("..\\Logs\\IS4\\IS4.log", LogEventLevel.Information,
            //            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
            //            null, 1073741824, null, true, false, TimeSpan.FromSeconds(1), RollingInterval.Day, true, 31, null, null)
            //.CreateLogger();

            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile( "appsettings.json", false, true)
                .Build();

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .CreateLogger();

            Log.Information("Logging from IS4 Program.cs - IS4 starting up");

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