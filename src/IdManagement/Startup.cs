using IdManagement.Services.HealthCheck;
using IdManagement.Services.Logging;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Polly;
using Serilog;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace IdManagement
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews(AppConfig.MVCControllerOptions);

            services.AddHttpClient();

            //TO COMPLETE:
            //https: //github.com/Xabaril/AspNetCore.Diagnostics.HealthChecks?WT.mc_id=-blog-scottha  
            //https: //volosoft.com/Blog/Using-Health-Checks-in-ASP.NET-Boilerplate
            //https: //github.com/Xabaril/AspNetCore.Diagnostics.HealthChecks/blob/master/samples/HealthChecks.Sample/Startup.cs
            services.AddHealthChecks()
                    .AddIdentityServer(new Uri(AppConfig.IS4_BASE_URL))
                    .AddCheck<SystemMemoryHealthCheck>("Memory")
                    //AppConfig.CLIENT_ID string to get a Named HttpClient initiallized below in the services.AddClientAccessTokenClient extension method from Identity Model.
                    //The method and client retrieve an access token which is required to do the Health Check of the IdApi. 
                    //param 1) AppConfig.CLIENT_ID and _httpClientFactory from IoC to use named httpclient
                    //param 2) the controller and action to test health
                    .AddTypeActivatedCheck<IdApiHealthCheck>("IdApi", failureStatus: HealthStatus.Unhealthy, tags: new[] { "IdApiHealthCheckTag" }, args: new object[] { AppConfig.CLIENT_ID, "Token/Healthz" });

            services.AddLogging();

            //CHANGE THIS OUT FOR PRODUCTION
            services.AddDistributedMemoryCache();

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            services.AddAuthentication(AppConfig.AuthOptions)
                    .AddCookie(AppConfig.COOKIE, AppConfig.CookieOptions)
                    .AddOpenIdConnect(AppConfig.OIDC, AppConfig.OidcOptions);

            services.AddAccessTokenManagement(AppConfig.AccessTokenManagment)
                    .ConfigureBackchannelHttpClient()
                    .AddTransientHttpErrorPolicy(policy => policy.WaitAndRetryAsync(new[]
                    {
                        TimeSpan.FromSeconds(1),
                        TimeSpan.FromSeconds(2),
                        TimeSpan.FromSeconds(3)
                    })); 

            services.AddUserAccessTokenClient("user_client", client => client.BaseAddress = new Uri(AppConfig.ID_API_BASE_URL + "/"));

            services.AddClientAccessTokenClient(AppConfig.CLIENT_ID, configureClient: client => client.BaseAddress = new Uri(AppConfig.ID_API_BASE_URL + "/"));
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //https: //docs.microsoft.com/en-us/dotnet/csharp/programming-guide/exceptions/
            //https: //docs.microsoft.com/en-us/dotnet/csharp/programming-guide/exceptions/creating-and-throwing-exceptions
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseStatusCodePages();
                app.UseStatusCodePagesWithReExecute("/Error/{0}");

                //If the proxy server also handles writing HSTS headers (for example, native HSTS support in IIS 10.0 (1709) or later),
                //HSTS Middleware isn't required by the app. For more information, see Opt-out of HTTPS/HSTS on project creation.
                //https: //docs.microsoft.com/en-us/aspnet/core/security/enforcing-ssl?view=aspnetcore-3.1&tabs=visual-studio
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();//Can be handled by reverse proxy as can UseHsts()

            app.UseStaticFiles();

            app.UseSerilogRequestLogging(options =>
            {
                options.EnrichDiagnosticContext = LogHelper.EnrichFromRequest;
                options.GetLevel = LogEventLevelHelper.CustomGetLevel;
            });
            

            app.UseHealthChecks("/healthz", AppHealthCheckOpts.HealthCheckOpts());

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHealthChecks("/healthz").RequireAuthorization();
                //https: //docs.microsoft.com/en-us/aspnet/core/fundamentals/routing?view=aspnetcore-3.0#endpoint-routing-differences-from-earlier-versions-of-routing
                //https: //docs.microsoft.com/en-us/aspnet/core/fundamentals/routing?view=aspnetcore-3.1#routing-basics
                endpoints.MapDefaultControllerRoute().RequireAuthorization();
            });
        }
    }
}
