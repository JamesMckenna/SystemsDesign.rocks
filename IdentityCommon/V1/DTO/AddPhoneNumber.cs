using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class AddPhoneNumber
    {
        public AddPhoneNumber() { }

        public string Id { get; set; }

        public string PhoneNumber { get; set; }

        public string Code { get; set; }
    }
}
