using TestSoln.Infra.IoC;
using TestSoln.App.Configurations;
using TestSoln.App.Middlewares;
using TestSoln.Application.ViewModel;
using TestSoln.Data.Context;
using TestSoln.Services.Services;
using TestSoln.Common;
using TestSoln.Common.Logging;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.ApplicationInsights.DependencyCollector;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Reflection;

namespace TestSoln.App
{
    public class Startup
    {
        public const string AppVersionKey = "apiv";

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        /// <value>
        /// The configuration.
        /// </value>
        public IConfiguration Configuration { get; }
        /// <summary>
        /// Gets or sets Configuration.
        /// </summary>
        public ILogger Logger { get; set; }
        // use it for logging during host construction

        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            this.Environment = env;
            Configuration = configuration;
        }
        /// <summary>
        /// Gets version of current assembly.
        /// </summary>
        /// <value>
        /// The application version.
        /// </value>
        public static string AppVersion => Assembly.GetExecutingAssembly().GetName().Version.ToString();
        public IWebHostEnvironment Environment { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            this.ConfigureAppInsights(services);
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApi(Configuration, "AzureAd");
            services.AddAuthorization(options =>
            {
                options.AddPolicy("AdministratorPolicy", policy =>
                {
                    policy.Requirements.Add(new UserRoleRequirement("Admin"));
                });
            });
            KeyVault.InitializeApplicationSetting(this.Configuration);
            string wavespaceDbConnectionString = KeyVault.GetConnectionString().Result;

            if (!string.IsNullOrEmpty(this.Configuration.GetSection("CORSSettings").GetValue<string>("AllowedOrigins")))
            {
                services.AddCors(
                options =>
                {
                    options.AddPolicy(
                        "CorsPolicy",
                        builder =>
                        {
                            builder.SetIsOriginAllowedToAllowWildcardSubdomains();
                            builder.WithOrigins(this.Configuration.GetSection("CORSSettings").GetValue<string>("AllowedOrigins").Split(new char[] { ',' }, StringSplitOptions.None));
                            builder.AllowAnyMethod();
                            builder.AllowAnyHeader();
                            builder.AllowCredentials().WithExposedHeaders(AppVersionKey);
                        });
                });
            }
            this.ConfigureCaching(services);
            services.AddDbContext<WavespaceContext>(options =>
                 options.UseSqlServer(wavespaceDbConnectionString));
            services.AddControllers(config => { 
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddRequirements(new UserRoleRequirement("Admin"))
                    .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            }).AddFluentValidation(fvc => fvc.RegisterValidatorsFromAssemblyContaining<Startup>())
            .AddNewtonsoftJson(options =>
                options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore);
            this.ConfigureSwagger(services);            
            RegisterServices(services, this.Configuration);
            services.RegisterAutoMapper();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseMiddleware<ErrorHandlerMiddleware>();

            this.Logger = loggerFactory.CreateLogger<Startup>();

            this.AddSwagger(app);
            app.UseForwardedHeaders();
            app.UseStaticFiles();
            app.UseCors("CorsPolicy");

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseHttpsRedirection();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        private static void RegisterServices(IServiceCollection services, IConfiguration configuration)
        {
            DependencyBootstraper.RegisterServices(services, configuration);
        }

        private void ConfigureCaching(IServiceCollection services)
        {
            services.AddMemoryCache();
            services.AddDistributedMemoryCache();
        }

        /// <summary>
        /// Adds the swagger.
        /// </summary>
        /// <param name="app">The application.</param>
        private void AddSwagger(IApplicationBuilder app)
        {
            if (this.Environment.EnvironmentName.StartsWith("Prod", StringComparison.InvariantCultureIgnoreCase))
            {
                return;
            }

            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.OAuthClientId(this.Configuration["Swagger:ClientId"]);
                c.OAuthAdditionalQueryStringParams(new Dictionary<string, string>() { { "resource", this.Configuration["AzureAD:ClientId"] } });
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "wavespace API v1");
            });
        }

        /// <summary>
        /// Configures Swagger.
        /// </summary>
        /// <param name="services">service.</param>
        private void ConfigureSwagger(IServiceCollection services)
        {
            if (this.Environment.EnvironmentName.StartsWith("Prod", StringComparison.InvariantCultureIgnoreCase))
            {
                return;
            }

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "TestSoln API", Version = "v1" });
                c.CustomSchemaIds((type) => type.FullName);
                c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        Implicit = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = new Uri($"{this.GetBaseOauth2Url()}/oauth2/authorize", UriKind.Absolute),
                            TokenUrl = new Uri($"{this.GetBaseOauth2Url()}/oauth2/token", UriKind.Absolute),
                        },
                    },
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "oauth2" },
                        },
                        Array.Empty<string>()
                    },
                });
                c.DescribeAllParametersInCamelCase();
            });
        }

        /// <summary>
        /// Configure Application Insights.
        /// </summary>
        /// <param name="services">services.</param>
        private void ConfigureAppInsights(IServiceCollection services)
        {
            services.AddApplicationInsightsTelemetry(aiOptions => this.Configuration.Bind("ApplicationInsightsServiceOptions", aiOptions));
            services.ConfigureTelemetryModule<DependencyTrackingTelemetryModule>((module, o) =>
            {
                module.EnableSqlCommandTextInstrumentation = true;
                this.Configuration.Bind("DependencyCollectionOptions", module);
            });
            services.AddSingleton<ITelemetryInitializer, AuthenticatedUserContextTelemetryInitializer>();
        }
        private string GetBaseOauth2Url()
        {
            return $"{this.Configuration["AzureAd:Instance"]}{this.Configuration["AzureAd:TenantId"]}";
        }
    }
}
