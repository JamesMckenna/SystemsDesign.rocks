using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;

namespace IdApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("default", policy =>
                {
                    policy.WithOrigins("https://localhost:5002", "https://localhost:5001")
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

            services.AddControllers();
            services.AddMvcCore(options =>
            {
                //lock down this Api to only allow access tokens with IdApi scope
                var policy = ScopePolicy.Create("IdApi");
                options.Filters.Add(new AuthorizeFilter(policy));
            })
            //https://stackoverflow.com/questions/55666826/where-did-imvcbuilder-addjsonoptions-go-in-net-core-3-0
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNamingPolicy = null;
                options.JsonSerializerOptions.DictionaryKeyPolicy = null;
            })
            .AddAuthorization(options =>
            {
                options.AddPolicy("ApiScope", policy =>
                {
                    policy.RequireScope("IdApi");
                    policy.RequireAuthenticatedUser();
                    policy.RequireClaim("scope", "IdApi");
                });
            });

            services.AddDistributedMemoryCache();

            services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
            .AddIdentityServerAuthentication("IdentityServerAccessToken", options =>
            {
                options.Authority = "https://localhost:5001";
                options.ApiName = "IdApi";
                options.ApiSecret = "secret";

                //Using Reference Tokens - lessons calls to IS4 to validate tokens
                options.EnableCaching = true; //REQUIRES: services.AddDistributedMemoryCache();
                options.CacheDuration = TimeSpan.FromMinutes(2);
                //options.DiscoveryDocumentRefreshInterval = TimeSpan.FromSeconds(100);
                options.SupportedTokens = SupportedTokens.Both;
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseCors("default");

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(name: "Token", pattern: "Token/{action}", defaults: new { controller = "Token", action = "Get" });

                endpoints.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}")
                         .RequireAuthorization("ApiScope");
            });
        }
    }
}
