using IdentityServer4.Models;
using Microsoft.AspNetCore.Diagnostics;

namespace IS4.Models
{
    public class ErrorViewModel
    {
        public ErrorViewModel(){ }

        //Identity Server 4
        public ErrorViewModel(string error)
        {
            Error = new ErrorMessage { Error = error };
        }
        //Identity Server 4
        public ErrorMessage Error { get; set; }

        public ErrorViewModel(string requestId, string detail, string title, int statusCode, string emoji)
        {
            RequestId = requestId.Trim();
            Detail = detail.Trim();
            Title = title.Trim();
            StatusCode = statusCode;
            Emoji = emoji;
        }
        public string RequestId { get; private set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
        public string Detail { get; private set; }
        public string Title { get; private set; }

        //I ADDED
        public int? StatusCode { get; private set; }
        public string Emoji { get; private set; }
    }
}
