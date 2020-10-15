using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class RegisterAccount
    {
        [Required(ErrorMessage = "A Username must be provided to create a new account.")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "A valid email address is required to create a new account.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "A password is required to create a new account.")]
        public string Password { get; set; }

        public string UrlEncodedVerificationCode {get; set;}

        public string Id { get; set; }
    }
}
