namespace IS4.Services.SecurityHeaders.Constants
{
    public static class StrictTransportSecurityConstants
    {
        public static readonly string Header = "Strict-Transport-Security";

        public static readonly string MaxAge = "max-age={0}";

        public static readonly string MaxAgeIncludeSubdomains = "max-age={0}; includeSubDomains";

        public static readonly string NoCache = "max-age=0";
    }
}
