using System.ComponentModel.DataAnnotations;
namespace IdentityCommon.V1.DTO
{
    public class ChangePassword
    {
        public string OldPassword { get; set; }

        public string NewPassword { get; set; }

        public string Id { get; set; }
    }

}
