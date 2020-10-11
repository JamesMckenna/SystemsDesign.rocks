using System.ComponentModel.DataAnnotations;
namespace IdentityCommon.V1.DTO
{
    public class ChangePassword
    {
        [Required(ErrorMessage = "Current password must be supplied.")]
        public string OldPassword { get; set; }

        [Required(ErrorMessage = "A new password is required.")]
        public string NewPassword { get; set; }

        public string Id { get; set; }
    }

}
