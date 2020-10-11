namespace IdentityCommon.V1.DTO
{
    public class RegisterAccountResponse
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string UrlEncodedVerificationCode { get; set; }
    }
}
