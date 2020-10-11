namespace IdentityCommon.V1.DTO
{
    public class UserAccount
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public bool TwoFactor { get; set; }
        public string PhoneNumber { get; set; }
        public bool IsEmailConfirmed { get; set; }
    }
}
