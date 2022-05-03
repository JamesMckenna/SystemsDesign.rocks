using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class RegisterAccount
    {
        public string UserName { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }

        public string UrlEncodedVerificationCode {get; set;}

        public string Id { get; set; }
    }
}
