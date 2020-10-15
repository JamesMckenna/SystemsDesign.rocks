using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class ForgotPassword
    {
        [Required(ErrorMessage = "An vaild email must be supplied to reset the account password")]
        [EmailAddress(ErrorMessage = "An vaild email must be supplied to reset the account password")]
        public string Email { get; set; }

        public string Code { get; set; }
    }
}
