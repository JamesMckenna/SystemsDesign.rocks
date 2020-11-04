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
            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(@"C:\Secrets\"))
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
                //options.Cookie.Expiration = TimeSpan.FromSeconds(Double.Parse(Configuration["LifeTimes:SessionCookieExpireSeconds"].ToString()));
            });

            services.AddHsts(options =>
            {
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(365);
                options.Preload = true;
            });

            services.AddControllersWithViews(options => options.Filters.Add<LoggingActionFilter>());

            services.AddLogging();

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(Configuration["IS4ConnectionStrings:DefaultConnection"]));

            services.AddIdentity<ApplicationUser, IdentityRole>(AppIdentityOptions.App_Identity_Options)
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var builder = services.AddIdentityServer(AppIS4Options.App_IS4_Options)
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(Config.ApiScopes)
                .AddInMemoryApiResources(Config.ApiResources)
                .AddInMemoryClients(Config.Clients)
                .AddAspNetIdentity<ApplicationUser>();

            // not recommended for production - you need to store your key material somewhere secure
            builder.AddDeveloperSigningCredential();
            
            //services.AddAuthentication().AddCookie("Cookies");//way it was configured for Shared cookie between IS4 and IdManagement: probably don't need a shared cookie if I make IdManagement is both a client and a resource.
            services.AddAuthentication("Cookies").AddCookie("Cookies");
            services.ConfigureApplicationCookie(AppCookieOptions.CookieAuthOptions);
            services.Configure<CookiePolicyOptions>(AppCookieOptions.CookiePolicy);

            services.ConfigureNonBreakingSameSiteCookies();//see AppCookieOptions.cs
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment Environment)
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
                  .AddCustomHeader("Content-Security-Policy", "frame-ancestors 'self' https://localhost:443/;")
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
