using IdentityServer.Infrastructure.Data.Entities;

namespace IdentityServer.Infrastructure.Factories;

public class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser>
{
    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        var roles = await UserManager.GetRolesAsync(user);

        identity.AddClaims(roles.Select(role => new Claim(JwtClaimTypes.Role, role)));

        return identity;
    }
}

