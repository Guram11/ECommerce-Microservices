using BuildingBlocks.Errors;
using BuildingBlocks.Wrappers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Text;

namespace BuildingBlocks.Extensions;
public static class JwtAuthenticationExtensions
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(o =>
        {
            o.RequireHttpsMetadata = false;
            o.SaveToken = false;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = configuration["JWTSettings:Issuer"],
                ValidAudience = configuration["JWTSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTSettings:Key"] ?? string.Empty))
            };
            o.Events = new JwtBearerEvents()
            {
                OnAuthenticationFailed = context =>
                {
                    // Check if the response has already started, skip setting status if it has
                    if (context.Response.HasStarted)
                    {
                        return Task.CompletedTask;
                    }

                    context.NoResult();
                    context.Response.ContentType = "application/json";

                    // Check if the exception is due to an expired token
                    if (context.Exception is SecurityTokenExpiredException)
                    {
                        context.Response.StatusCode = 401;
                        var result = Result<object>.Failure(AuthErrors.TokenNoLongerActive());
                        var resultJson = JsonConvert.SerializeObject(result);
                        return context.Response.WriteAsync(resultJson);
                    }

                    // For general authentication failure, return a generic error response
                    context.Response.StatusCode = 500;
                    var generalFailureResult = Result<object>.Failure(AuthErrors.Unauthorized());
                    var failureResultJson = JsonConvert.SerializeObject(generalFailureResult);
                    return context.Response.WriteAsync(failureResultJson);
                },
                OnChallenge = context =>
                {
                    if (context.Response.HasStarted)
                    {
                        return Task.CompletedTask;
                    }

                    context.HandleResponse();
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    var result = Result<object>.Failure(AuthErrors.Unauthorized());
                    var resultJson = JsonConvert.SerializeObject(result);
                    return context.Response.WriteAsync(resultJson);
                },
                OnForbidden = context =>
                {
                    if (context.Response.HasStarted)
                    {
                        return Task.CompletedTask;
                    }

                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    var result = Result<object>.Failure(AuthErrors.Forbidden());
                    var resultJson = JsonConvert.SerializeObject(result);
                    return context.Response.WriteAsync(resultJson);
                },
            };
        });

        return services;
    }
}
