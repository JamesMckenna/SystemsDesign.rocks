using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class ResetPassword
    {
        [Required(ErrorMessage = "A reset password code is required.")]
        public string Code { get; set; }

        [Required(ErrorMessage = "A User email must be provided for the password reset process.")]
        public string Email { get; set; }

        [Required(ErrorMessage ="A password is required for the password reset process.")]
        public string Password { get; set; }
    }
}
