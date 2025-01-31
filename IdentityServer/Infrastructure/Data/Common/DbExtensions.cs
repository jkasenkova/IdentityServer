using Npgsql.EntityFrameworkCore.PostgreSQL.Infrastructure;

namespace IdentityServer.Infrastructure.Data.Common;

public static class DbExtensions
{
    public static void NpgsqlOptionsAction(NpgsqlDbContextOptionsBuilder npgsqlDbContextOptionsBuilder)
    {
        npgsqlDbContextOptionsBuilder.MigrationsAssembly(typeof(Program).GetTypeInfo().Assembly.GetName().Name);
    }

    public static void ResolveDbContextOptions(IServiceProvider serviceProvider, DbContextOptionsBuilder dbContextOptionsBuilder)
    {
        dbContextOptionsBuilder.UseNpgsql(
            serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString("IdentityServer"),
            NpgsqlOptionsAction);
    }
}
