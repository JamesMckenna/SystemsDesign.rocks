namespace IS4.Services.SecurityHeaders.Constants
{
    public static class XssProtectionConstants
    {
        public static readonly string Header = "X-XSS-Protection";

        public static readonly string Enabled = "1";

        public static readonly string Disabled = "0";

        public static readonly string Block = "1; mode=block";

        public static readonly string Report = "1; report={0}";
    }
}
