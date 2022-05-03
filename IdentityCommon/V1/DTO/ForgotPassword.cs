using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class ForgotPassword
    {
        public string Email { get; set; }

        public string Code { get; set; }
    }
}
