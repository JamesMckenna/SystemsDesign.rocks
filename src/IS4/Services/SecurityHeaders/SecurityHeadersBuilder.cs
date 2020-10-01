using IS4.Services.SecurityHeaders.Constants;

namespace IS4.Services.SecurityHeaders
{
    public class SecurityHeadersBuilder
    {
        private readonly SecurityHeadersPolicy _policy = new SecurityHeadersPolicy();
        public const int OneYearInSeconds = 60 * 60 * 24 * 365;

        public SecurityHeadersBuilder AddDefaultSecurePolicy()
        {
            AddFrameOptionsDeny();
            AddXssProtectionBlock();
            AddContentTypeOptionsNoSniff();
            AddStrictTransportSecurityMaxAge();
            RemoveServerHeader();

            return this;
        }

        public SecurityHeadersBuilder AddFrameOptionsDeny()
        {
            _policy.SetHeaders[FrameOptionsConstants.Header] = FrameOptionsConstants.Deny;
            return this;
        }

        public SecurityHeadersBuilder AddFrameOptionsSameOrigin()
        {
            _policy.SetHeaders[FrameOptionsConstants.Header] = FrameOptionsConstants.SameOrigin;
            return this;
        }

        public SecurityHeadersBuilder AddFrameOptionsSameOrigin(string uri)
        {
            _policy.SetHeaders[FrameOptionsConstants.Header] = string.Format(FrameOptionsConstants.AllowFromUri, uri);
            return this;
        }

        public SecurityHeadersBuilder AddXssProtectionEnabled()
        {
            _policy.SetHeaders[XssProtectionConstants.Header] = XssProtectionConstants.Enabled;
            return this;
        }

        public SecurityHeadersBuilder AddXssProtectionDisabled()
        {
            _policy.SetHeaders[XssProtectionConstants.Header] = XssProtectionConstants.Disabled;
            return this;
        }

        public SecurityHeadersBuilder AddXssProtectionBlock()
        {
            _policy.SetHeaders[XssProtectionConstants.Header] = XssProtectionConstants.Block;
            return this;
        }

        public SecurityHeadersBuilder AddXssProtectionReport(string reportUrl)
        {
            _policy.SetHeaders[XssProtectionConstants.Header] =
                string.Format(XssProtectionConstants.Report, reportUrl);
            return this;
        }

        public SecurityHeadersBuilder AddStrictTransportSecurityMaxAge(int maxAge = OneYearInSeconds)
        {
            _policy.SetHeaders[StrictTransportSecurityConstants.Header] =
                string.Format(StrictTransportSecurityConstants.MaxAge, maxAge);
            return this;
        }

        public SecurityHeadersBuilder AddStrictTransportSecurityMaxAgeIncludeSubDomains(int maxAge = OneYearInSeconds)
        {
            _policy.SetHeaders[StrictTransportSecurityConstants.Header] =
                string.Format(StrictTransportSecurityConstants.MaxAgeIncludeSubdomains, maxAge);
            return this;
        }

        public SecurityHeadersBuilder AddStrictTransportSecurityNoCache()
        {
            _policy.SetHeaders[StrictTransportSecurityConstants.Header] =
                StrictTransportSecurityConstants.NoCache;
            return this;
        }

        public SecurityHeadersBuilder AddContentTypeOptionsNoSniff()
        {
            _policy.SetHeaders[ContentTypeOptionsConstants.Header] = ContentTypeOptionsConstants.NoSniff;
            return this;
        }

        public SecurityHeadersBuilder RemoveServerHeader()
        {
            _policy.RemoveHeaders.Add(ServerConstants.Header);
            return this;
        }

        public SecurityHeadersBuilder AddCustomHeader(string header, string value)
        {
            _policy.SetHeaders[header] = value;
            return this;
        }

        public SecurityHeadersBuilder RemoveHeader(string header)
        {
            _policy.RemoveHeaders.Add(header);
            return this;
        }

        public SecurityHeadersPolicy Build()
        {
            return _policy;
        }
    }
}
