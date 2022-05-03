using System.ComponentModel.DataAnnotations;

namespace IdManagement.Models.AccountViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [RegularExpression(@"^[a-zA-Z0-9-._+]{4,25}$", ErrorMessage = "Upper or lowercase English letters a - z, numbers 0 - 9, and - . _ + are valid characters for User Name")]
        [StringLength(25, ErrorMessage = "{0} must be unique and between {2} and {1} characters long.", MinimumLength = 4)]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "A unique email must be provided to create an account.")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(25, ErrorMessage = "The {0} must be between {2} and {1} characters long .", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [RegularExpression(@"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,25}$", ErrorMessage = "Your password must be at least 6 characters long, contain at least 1 uppercase, at least 1 lowercase, at least 1 letter, at least 1 number and at least 1 of the following special characters # ? ! @ $ % ^ & * -")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
