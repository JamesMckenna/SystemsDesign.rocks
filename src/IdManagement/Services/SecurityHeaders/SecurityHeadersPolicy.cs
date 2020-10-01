using System.Collections.Generic;

namespace IdManagement.Services.SecurityHeaders
{
    public class SecurityHeadersPolicy
    {
        public IDictionary<string, string> SetHeaders { get; } = new Dictionary<string, string>();

        public ISet<string> RemoveHeaders { get; } = new HashSet<string>();
    }
}
