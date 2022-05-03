using System.ComponentModel.DataAnnotations;

namespace IdManagement.Models.AccountViewModels
{
    public class VerifyPhoneNumberViewModel
    {
        [Required]
        public string Code { get; set; }

        [Required(ErrorMessage = "A vaild phone number must be provided.")]
        [Phone(ErrorMessage = "A vaild phone number was not provided.")]
        [Display(Name = "Phone number")]
        public string PhoneNumber { get; set; }

        public string Id { get; set; }
    }
}
