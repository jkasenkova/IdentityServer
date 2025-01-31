using IdentityServer.Infrastructure.Data.Entities;

namespace IdentityServer.Infrastructure.Data.Common;

public class SeedDatabase
{
    private readonly IConfiguration _configuration;
    private readonly ApplicationDbContext _dbContext;
    private readonly ConfigurationDbContext _configurationDbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    private const string BuyerRoleName = "Buyer";
    private const string ManagerRoleName = "Manager";

    public SeedDatabase(
        IConfiguration configuration,
        ApplicationDbContext dbContext,
        ConfigurationDbContext configurationDbContext,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager)
    {
        _configuration = configuration;
        _dbContext = dbContext;
        _configurationDbContext = configurationDbContext;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task Seed()
    {
        await _dbContext.Database.EnsureCreatedAsync();

        if (!await _roleManager.RoleExistsAsync(BuyerRoleName))
        {
            await _roleManager.CreateAsync(new IdentityRole(BuyerRoleName));
        }

        if (!await _roleManager.RoleExistsAsync(ManagerRoleName))
        {
            await _roleManager.CreateAsync(new IdentityRole(ManagerRoleName));
        }

        if (await _userManager.FindByNameAsync("buyer.user") is null)
        {
            var buyerUser = new ApplicationUser
            {
                EmailConfirmed = true,
                UserName = "buyer.user",
                Email = "buyer.user@example.com"
            };

            await _userManager.CreateAsync(buyerUser, "Pa55w0rd!");
            await _userManager.AddToRoleAsync(buyerUser, BuyerRoleName);
        }

        if (await _userManager.FindByNameAsync("manager.user") is null)
        {
            var managerUser = new ApplicationUser
            {
                EmailConfirmed = true,
                UserName = "manager.user",
                Email = "manager.user@example.com"
            };
            await _userManager.CreateAsync(managerUser, "Pa55w0rd!");
            await _userManager.AddToRoleAsync(managerUser, ManagerRoleName);
        }

        if (!await _configurationDbContext.ApiResources.AnyAsync())
        {
            await _configurationDbContext.ApiResources.AddAsync(new ApiResource
            {
                Name = _configuration["AuthSettings:ApiResourceName"]!,
                DisplayName = "API",
                Scopes = new List<string> { _configuration["AuthSettings:ScopeName"]! },
                UserClaims = { JwtClaimTypes.Role }
            }.ToEntity());

            await _configurationDbContext.SaveChangesAsync();
        }

        if (!await _configurationDbContext.ApiScopes.AnyAsync())
        {
            await _configurationDbContext.ApiScopes.AddAsync(new ApiScope
            {
                Name = _configuration["AuthSettings:ScopeName"]!,
                DisplayName = "API",
                UserClaims = { JwtClaimTypes.Role }
            }.ToEntity());

            await _configurationDbContext.SaveChangesAsync();
        }

        if (!await _configurationDbContext.Clients.AnyAsync())
        {
            await _configurationDbContext.Clients.AddRangeAsync(
                new Client
                {
                    ClientId = _configuration["AuthSettings:ClientId"]!,
                    ClientSecrets = new List<Secret> { new(_configuration["AuthSettings:ClientSecret"].Sha512()) },
                    ClientName = _configuration["AuthSettings:ClientName"],
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
                    AllowedScopes = new List<string> { _configuration["AuthSettings:ScopeName"]! },
                    AlwaysSendClientClaims = true,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration = TokenExpiration.Absolute,
                    UpdateAccessTokenClaimsOnRefresh = true,
                }.ToEntity());

            await _configurationDbContext.SaveChangesAsync();
        }

        if (!await _configurationDbContext.IdentityResources.AnyAsync())
        {
            await _configurationDbContext.IdentityResources.AddRangeAsync(
                new IdentityResources.OpenId().ToEntity(),
                new IdentityResources.Profile().ToEntity(),
                new IdentityResources.Email().ToEntity());

            await _configurationDbContext.SaveChangesAsync();
        }
    }
}