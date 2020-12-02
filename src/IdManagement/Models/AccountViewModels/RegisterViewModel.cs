using System.ComponentModel.DataAnnotations;

namespace IdManagement.Models.AccountViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [RegularExpression(@"^[a-zA-Z0-9-._+]{4,25}$", ErrorMessage = "Upper or lowercase English letters a - z, numbers 0 - 9, and - . _ + are valid characters for User Name")]
        [StringLength(25, ErrorMessage = "User Name must be unique and at least {0} characters long.", MinimumLength = 4)]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The password must be at least {0} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
