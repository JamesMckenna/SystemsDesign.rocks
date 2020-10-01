namespace IdManagement.Services.SecurityHeaders
{
    public class FrameOptionsConstants
    {
        public static readonly string Header = "X-Frame-Options";

        public static readonly string Deny = "DENY";

        public static readonly string SameOrigin = "SAMEORIGIN";

        public static readonly string AllowFromUri = "ALLOW-FROM {0}";
    }
}
