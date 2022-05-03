using System.ComponentModel.DataAnnotations;

namespace IdManagement.Models.AccountViewModels
{
    public class SetPasswordViewModel
    {
        [Required]
        [StringLength(25, ErrorMessage = "The {0} must be between {2} and {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        [RegularExpression(@"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,25}$", ErrorMessage = "Your password must be at least 6 characters long, contain at least 1 uppercase, at least 1 lowercase, at least 1 letter, at least 1 number and at least 1 of the following special characters # ? ! @ $ % ^ & * -")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
