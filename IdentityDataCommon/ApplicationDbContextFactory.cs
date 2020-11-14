using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace IdentityDataCommon
{
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            //this doesn't work if the code is not run - EG: Dotnet run. A developer uses a class library, but doesn't run it.
            //string environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"); //Get environment doesn't work even if there is a launchSettings.json in the library. 
            //string secretsFile = Environment.GetEnvironmentVariable("SECRETS_PATH"); //Get environment doesn't work even if there is a launchSettings.json in the library.

            //Build config
            IConfiguration _configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                //Since this is a designtime operation, a hardcoded value to perform a EntityFramework Migration is not the end of the world.
                .AddJsonFile("C:\\Secrets\\AppSecrets.json", optional: false, reloadOnChange: true)
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
            optionsBuilder.UseSqlServer(_configuration["IdApiConnectionStrings:IdentityDB"]);

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}