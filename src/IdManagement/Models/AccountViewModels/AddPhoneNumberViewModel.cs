using System.ComponentModel.DataAnnotations;

namespace IdManagement.Models.AccountViewModels
{
    public class AddPhoneNumberViewModel
    {
        [Required(ErrorMessage = "A vaild phone number was not provided.")]
        [Phone(ErrorMessage = "A vaild phone number was not provided.")]
        [Display(Name = "Phone number")]
        public string PhoneNumber { get; set; }

        public string Id { get; set; }

        public string Code { get; set; }
    }
}
