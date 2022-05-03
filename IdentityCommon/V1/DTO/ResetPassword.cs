using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class ResetPassword
    {
        public string Code { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }
    }
}
