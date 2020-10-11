using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class AddPhoneNumber
    {
        public AddPhoneNumber() { }

        [Required(AllowEmptyStrings = false,ErrorMessage ="A valid Id was not provided.")]
        public string Id { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "A phone number was not provided.")]
        [Phone(ErrorMessage = "A vaild phone number was not provided.")]
        public string PhoneNumber { get; set; }

        public string Code { get; set; }
    }
}
