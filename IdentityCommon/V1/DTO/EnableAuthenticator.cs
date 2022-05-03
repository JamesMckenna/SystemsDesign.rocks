using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class EnableAuthenticator
    {
        public string Id { get; set; }

        public string Code { get; set; }

        public string SharedKey { get; set; }

        public string AuthenticatorUri { get; set; }
        public string[] RecoveryCodes { get; set; }
    }
}
