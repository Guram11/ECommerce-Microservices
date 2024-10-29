using Auth.API.Domain.Enums;
using Auth.API.Domain.Models;
using Microsoft.AspNetCore.Identity;

namespace Auth.API.Seeds;

public static class DefaultBasicUser
{
    public static async Task SeedAsync(UserManager<ApplicationUser> userManager)
    {
        var defaultUser = new ApplicationUser
        {
            UserName = "basicuser",
            Email = "basicuser@gmail.com",
            FirstName = "John",
            LastName = "Doe",
            EmailConfirmed = true,
            PhoneNumberConfirmed = true
        };
        if (userManager.Users.All(u => u.Id != defaultUser.Id))
        {
            var user = await userManager.FindByEmailAsync(defaultUser.Email);
            if (user == null)
            {
                await userManager.CreateAsync(defaultUser, "123Pa$$word!");
                await userManager.AddToRoleAsync(defaultUser, Roles.Basic.ToString());
            }

        }
    }
}
