using IdApi.Services.ErrorHelpers;
using IdentityCommon;
using IdentityDataCommon;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using System;
using System.IO;
using System.Net.Mime;

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

            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Configuration["SECRETS_DIR"]))
                    .SetApplicationName(Configuration["Properties:ApplicationName"]);

            services.AddDbContext<ApplicationDbContext>(options => 
                options.UseSqlServer(Configuration["IdApiConnectionStrings:IdentityDB"], x => x.MigrationsAssembly("IdentityDataCommon")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()
                .AddSignInManager<SignInManager<ApplicationUser>>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._+";
                options.User.RequireUniqueEmail = false;
            });

            services.Configure<IISServerOptions>(options => { options.AutomaticAuthentication = false; });

            services.AddCors(options =>
            {
                options.AddPolicy("default", policy =>
                {
                    policy.WithOrigins(Configuration["AppURLS:IdManagementBaseUrl"], Configuration["AppURLS:IS4BaseUrl"])
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

            services.AddControllers()
            .ConfigureApiBehaviorOptions(options =>
            {
                options.SuppressModelStateInvalidFilter = true;
                options.SuppressInferBindingSourcesForParameters = true;

                options.InvalidModelStateResponseFactory = context =>
                {
                    var result = new BadRequestObjectResult(context.ModelState);
                    result.ContentTypes.Add(MediaTypeNames.Application.Json);
                    return result;
                };

            });

            services.AddMvcCore(options =>
            {
                //lock down this Api to only allow access tokens with IdApi scope
                var policy = ScopePolicy.Create("IdApi");
                options.Filters.Add(new AuthorizeFilter(policy));
                options.Filters.Add(typeof(ApiValidationFilterAttribute));
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

            services.AddLogging();
            services.AddDistributedMemoryCache();

            services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
            .AddOAuth2Introspection("introspection", options =>
            {
                options.Authority = Configuration["AppURLS:IS4BaseUrl"];
                options.ClientId = Configuration["AppIds:IdManagementId"];
                options.ClientSecret = Configuration["AppSecrets:IdManagementId"];
            })
            .AddIdentityServerAuthentication("IdentityServerAccessToken", options =>
            {
                options.Authority = Configuration["AppURLS:IS4BaseUrl"];
                options.ApiName = Configuration["ApplicationIds:IdApiId"];
                options.ApiSecret = Configuration["ApplicationSecrets:IdApiSecret"];

                //Using Reference Tokens - lessons calls to IS4 to validate tokens
                options.EnableCaching = true; //REQUIRES: services.AddDistributedMemoryCache();
                options.CacheDuration = TimeSpan.FromMinutes(2);
                options.SupportedTokens = SupportedTokens.Both;
            });

            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "IdApi", Version = "v1" });
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseMiddleware<AppErrorMiddleware>();

            app.UseSwagger(context => {
                context.RouteTemplate = Configuration["SwaggerOptions:JsonRoute"];
            });
            app.UseSwaggerUI(context => {
                string swaggerJsonBasePath = string.IsNullOrWhiteSpace(context.RoutePrefix) ? "." : "..";
                context.SwaggerEndpoint("./" + Configuration["SwaggerOptions:UIEndpoint"], Configuration["SwaggerOptions:Description"]);
            });

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
