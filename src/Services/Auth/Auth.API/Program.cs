using Auth.API.Data;
using Auth.API.Domain.Models;
using Auth.API.Interfaces;
using Auth.API.Seeds;
using Auth.API.Services;
using BuildingBlocks.Messaging.MassTransit;
using BuildingBlocks.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

internal class Program
{
    private static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddMessageBroker(builder.Configuration);

        builder.Services.AddDbContext<DataContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("Database"),
            b => b.MigrationsAssembly(typeof(DataContext).Assembly.FullName)));

        builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<DataContext>()
            .AddDefaultTokenProviders();

        builder.Services.Configure<JWTSettings>(builder.Configuration.GetSection("JWTSettings"));

        builder.Services.AddTransient<IAuthService, AuthService>();
        builder.Services.AddScoped<ITokenBlacklistService, TokenBlacklistService>();
        builder.Services.AddDistributedMemoryCache();

        var app = builder.Build();

        using (var serviceScope = app.Services.CreateScope())
        {
            var dataContext = serviceScope.ServiceProvider.GetService<DataContext>();
            dataContext?.Database.EnsureCreated();

            var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            await DefaultRoles.SeedAsync(roleManager);
            await DefaultBasicUser.SeedAsync(userManager);
        }

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
            app.UseDeveloperExceptionPage();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
        app.Run();
    }
}