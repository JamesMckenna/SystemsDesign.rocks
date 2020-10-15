using System.ComponentModel.DataAnnotations;

namespace IdentityCommon.V1.DTO
{
    public class EnableAuthenticator
    {
        [Required(ErrorMessage = "A User Id is required.")]
        public string Id { get; set; }

        [Required(ErrorMessage = "A TOTP Code entered by User is required to complete 2fa set-up.")]
        public string Code { get; set; }

        [Required(ErrorMessage = "The shared key for 2fa is required. Should have been set by IdApi Action Method LoadSharedKeyAndQrCodeUriAsync, and returned to view's hidden input on the viewmodel")]
        public string SharedKey { get; set; }

        [Required(ErrorMessage = "The Authenticator Uri for 2fa is required. Should have been set by IdApi Action Method LoadSharedKeyAndQrCodeUriAsync, and returned to view's hidden input on the viewmodel")]
        public string AuthenticatorUri { get; set; }
        public string[] RecoveryCodes { get; set; }
    }
}
