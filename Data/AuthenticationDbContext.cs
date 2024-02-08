using Authentication.Models;
using Microsoft.EntityFrameworkCore;

namespace Authentication.Data
{
    public class AuthenticationDbContext :DbContext
    {
        public AuthenticationDbContext(DbContextOptions<AuthenticationDbContext> options):base(options)
        {

        }

        public DbSet<User> Users { get; set; }
    }
}
