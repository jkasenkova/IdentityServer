using IdentityServer.Infrastructure.Data;
using IdentityServer.Infrastructure.Data.Common;
using IdentityServer.Infrastructure.Data.Entities;
using IdentityServer.Infrastructure.Factories;

var builder = WebApplication.CreateBuilder(args);

var configuration = builder.Configuration;

builder.Services.AddDbContext<ApplicationDbContext>((serviceProvider, dbContextOptionsBuilder) =>
{
    dbContextOptionsBuilder.UseNpgsql(
        serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString("Identity"),
        DbExtensions.NpgsqlOptionsAction);
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>()
    .AddDefaultTokenProviders()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>()
    .AddConfigurationStore(configurationStoreOptions =>
    {
        configurationStoreOptions.ResolveDbContextOptions = DbExtensions.ResolveDbContextOptions;
    })
    .AddOperationalStore(operationalStoreOptions =>
    {
        operationalStoreOptions.ResolveDbContextOptions = DbExtensions.ResolveDbContextOptions;
    });

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseIdentityServer();
app.UseAuthorization();
app.MapRazorPages();

if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();

    await scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>().Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();

    var applicationDbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var configurationDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    var seedDatabase = new SeedDatabase(
        configuration,
        applicationDbContext,
        configurationDbContext,
        userManager,
        roleManager);

    await seedDatabase.Seed();
}

app.Run();