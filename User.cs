using System.Globalization;

namespace Authentication
{
    public class User
    {
        public String UserName { get; set; } = string.Empty;
        public byte[] passwordHash { get; set; }
        public byte[] passwordSalt { get; set; }
    }
}
