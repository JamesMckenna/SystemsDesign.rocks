// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityCommon;
using IdentityDataCommon;
using IS4.AppConfiguration;
using IS4.Services.Logging;
using IS4.Services.SecurityHeaders;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace IS4
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
            Config.SetDI(Configuration);
            AppCookieOptions.SetDI(Configuration);
            AppIS4Options.SetDI(Configuration);
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var rsaCert = new X509Certificate2(Path.Combine(Configuration["SECRETS_DIR"], "IS4OpenSsl.pfx"), "CertIS4");

            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Configuration["SECRETS_DIR"]))
                .SetApplicationName(Configuration["Properties:ApplicationName"]);

            services.AddCors(options =>
            {
                options.AddPolicy("IS4", policy =>
                {
                    policy.WithOrigins(Configuration["AppURLS:IdManagementBaseUrl"], Configuration["AppURLS:IdApiBaseUrl"], Configuration["AppURLS:MainClientBaseUrl"])
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });
            services.AddAntiforgery(options =>
            {
                options.Cookie.Name = Configuration["Properties:SharedAntiForgCookie"];
                options.SuppressXFrameOptionsHeader = true;
            });

            services.AddHsts(options =>
            {
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(365);
                options.Preload = true;
            });

            services.AddControllersWithViews(options => options.Filters.Add<LoggingActionFilter>());

            services.AddLogging();

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration["IS4ConnectionStrings:IdentityDB"]));

            services.AddIdentity<ApplicationUser, IdentityRole>(AppIdentityOptions.App_Identity_Options)
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var builder = services.AddIdentityServer(AppIS4Options.App_IS4_Options)
                .AddSigningCredential((X509Certificate2)rsaCert)
                .AddValidationKey((X509Certificate2)rsaCert)
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(Config.ApiScopes)
                .AddInMemoryApiResources(Config.ApiResources)
                .AddInMemoryClients(Config.Clients)
                .AddAspNetIdentity<ApplicationUser>();

            services.AddAuthentication("Cookies").AddCookie("Cookies");
            services.ConfigureApplicationCookie(AppCookieOptions.CookieAuthOptions);
            services.ConfigureNonBreakingSameSiteCookies();//see AppCookieOptions.cs
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment Environment, IConfiguration configuration)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseStatusCodePagesWithReExecute("/Error/Error", "?statusCode={0}");

                app.UseHsts();
            }

            app.UseHttpsRedirection();
           
            app.UseSecurityHeadersMiddleware(new SecurityHeadersBuilder()
                  .AddDefaultSecurePolicy()
                  .AddCustomHeader("Access-Control-Allow-Origin", "*")
                  .AddCustomHeader("Content-Security-Policy", $"frame-ancestors 'self' { configuration["AppURLS:MainClientBaseUrl"] };")
                );

            app.UseStaticFiles();

            app.UseSerilogRequestLogging(options =>
            {
                options.EnrichDiagnosticContext = LogHelper.EnrichFromRequest;
                options.GetLevel = LogEventLevelHelper.CustomGetLevel;
            });

            app.UseRouting();

            app.UseCookiePolicy();

            app.UseCors("IS4");

            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
