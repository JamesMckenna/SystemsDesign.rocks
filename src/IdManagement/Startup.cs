using IdentityCommon;
using IdentityDataCommon;
using IdManagement.AppConfiguration;
using IdManagement.Services.DataProtectionServices;
using IdManagement.Services.HealthCheck;
using IdManagement.Services.Logging;
using IdManagement.Services.MessageService;
using IdManagement.Services.SecurityHeaders;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Polly;
using Serilog;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;

namespace IdManagement
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            AppCookieOptions.SetDI(Configuration);
            AppOidcOptions.SetDI(Configuration);
            AppIdentityModelTokenManagement.SetDI(Configuration);
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            string IdManagementId = Configuration["ApplicationIds:IdManagementId"];
            string IdManagementURL = Configuration["AppURLS:IdManagementBaseUrl"];
            string IdApiURL = Configuration["AppURLS:IdApiBaseUrl"];
            string IS4URL = Configuration["AppURLS:IS4BaseUrl"];
            string MainClient = Configuration["AppURLS:MainClientBaseUrl"];

            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Configuration["SECRETS_DIR"]))
                .SetApplicationName(Configuration["Properties:ApplicationName"]);

            #region CORS Policy, CSP
            services.AddCors(options =>
            {
                options.AddPolicy("default", policy =>
                {
                    policy.WithOrigins(IdApiURL, IS4URL, MainClient).AllowAnyHeader().AllowAnyMethod();
                });
            });
            services.AddAntiforgery(options =>//Does this need to be in this app? Can I not just use the AntiForg cookie from IS4
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
            #endregion

            services.Configure<IISServerOptions>(options => { options.AutomaticAuthentication = false; });

            services.AddControllersWithViews(AppMvcOptions.MVCControllerOptions);

            services.AddHttpContextAccessor();
            services.AddHttpClient();
            services.AddHttpClient("IdApiAccount");


            //Eventually - Remove DB access and Indentity Core. Should all be through IdApi. Need to find a way to email from this app without having Identity as a dependency
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration["IdMangementConnectionStrings:IdentityDB"]));

            services.AddIdentityCore<ApplicationUser>(AppIdentityOptions.App_Identity_Options)
               .AddEntityFrameworkStores<ApplicationDbContext>()
               .AddSignInManager()
               .AddDefaultTokenProviders(); //Needed to generate tokens for password reset, change email, change phone number 2Fa. Should probably move send sms/email to IdApi

            #region Health Checks
            services.AddHealthChecks()
                    .AddIdentityServer(new Uri(IS4URL))
                    .AddCheck<SystemMemoryHealthCheck>("Memory")
                    //IdManagementId string to get a Named HttpClient initiallized below in the services.AddClientAccessTokenClient extension method from Identity Model.
                    //The method and client retrieve an access token which is required to do the Health Check of the IdApi. 
                    //param 1) IdManagementId and _httpClientFactory from IoC to use named httpclient
                    //param 2) the IdApi controller and action to test health
                    .AddTypeActivatedCheck<IdApiHealthCheck>("IdApi", failureStatus: HealthStatus.Unhealthy, tags: new[] { "IdApiHealthCheckTag" }, args: new object[] { IdManagementId, "Token/Healthz" });
            #endregion

            services.AddLogging();

            //CHANGE THIS OUT FOR PRODUCTION
            services.AddDistributedMemoryCache();

            JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

            //CURRENTLY NOT USED
            services.AddSession(options => {
                options.Cookie.Name = Configuration["Properties:IdManagementSessionCookie"];
                options.IdleTimeout = TimeSpan.FromMinutes(20);
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
            });

            services.AddAuthentication(AppAuthenticationOptions.AuthOptions)
               .AddCookie("Cookies", AppCookieOptions.CookieAuthOptions)
               .AddOpenIdConnect("oidc", AppOidcOptions.OpenIdOptions);
            services.Configure<CookiePolicyOptions>(AppCookieOptions.CookiePolicy);


            //changes all data protection tokens timeout period to 4 hours
            services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromHours(4));
            //Tokens sent for ForgotPassword & ConfirmRegister will expire 4 hours after sending email to user
            services.AddTransient<CustomEmailConfirmationTokenProvider<ApplicationUser>>();
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();

            #region Identity Model Token Management 
            services.AddAccessTokenManagement(AppIdentityModelTokenManagement.TokenManagementOptions)
                    .ConfigureBackchannelHttpClient()
                    .AddTransientHttpErrorPolicy(policy => policy.WaitAndRetryAsync(new[]
                    {
                        TimeSpan.FromSeconds(1),
                        TimeSpan.FromSeconds(2),
                        TimeSpan.FromSeconds(3)
                    }));

            //Identity Model creates Named HttpClient and sets the BaseUrl
            services.AddUserAccessTokenClient("user_client", client => client.BaseAddress = new Uri(IdApiURL + "/"));
            //Identity Model creates Named HttpClient and sets the BaseUrl
            services.AddClientAccessTokenClient(IdManagementId, configureClient: client => client.BaseAddress = new Uri(IdApiURL + "/"));
            #endregion
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            #region Exception Handling Middelware
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                //Will log unhandled exception as * unhandled * exception, 
                //then redirect httpcontext to an Error controller and action method to display an error page.
                app.UseExceptionHandler("/Error");
                app.UseStatusCodePagesWithReExecute("/Error/Error", "?statusCode={0}");

                //If the proxy server also handles writing HSTS headers (for example, native HSTS support in IIS 10.0 (1709) or later),
                //HSTS Middleware isn't required by the app. For more information, see Opt-out of HTTPS/HSTS on project creation.
                //https: //docs.microsoft.com/en-us/aspnet/core/security/enforcing-ssl?view=aspnetcore-3.1&tabs=visual-studio
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            #endregion

            app.UseHttpsRedirection();//Can be handled by reverse proxy as can UseHsts()

            app.UseSession();

            app.UseSecurityHeadersMiddleware(new SecurityHeadersBuilder()
                  .AddDefaultSecurePolicy()
                  .AddCustomHeader("X-My-Custom-Header", "From-MiddleWareFiles")//EXAMPLE
                );

            app.UseStaticFiles();

            #region Serilog Options
            //Will log unhandled exceptions from app.UseExceptionHandler("/Error"); as * HANDLED *. This will cause duplicate logs - one handled, one unhandled.
            //Added a filter to Serilog config to filter out Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware, 
            //preventing duplicate entiries but also remove the * unhandled * from the log entry
            app.UseSerilogRequestLogging(options =>
            {
                options.EnrichDiagnosticContext = Services.Logging.LogHelper.EnrichFromRequest;
                options.GetLevel = LogEventLevelHelper.CustomGetLevel;
            });
            #endregion

            app.UseHealthChecks("/Developer/Healthz", AppHealthCheckOpts.HealthCheckOpts());

            app.UseCookiePolicy();

            app.UseRouting();

            app.UseCors("default");

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHealthChecks("/Developer/Healthz").RequireAuthorization();
                endpoints.MapDefaultControllerRoute().RequireAuthorization();
            });
        }
    }
}
