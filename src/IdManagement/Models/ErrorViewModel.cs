using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using System;

namespace IdManagement.Models
{
    public class ErrorViewModel
    {
        public ErrorViewModel()
        {

        }

        public ErrorViewModel(string requestId, string detail, string title, int statusCode, IExceptionHandlerFeature context )
        {
            RequestId = requestId.Trim();
            Detail = detail.Trim();
            Title = title.Trim();
            StatusCode = statusCode;
            CurrentContext = context;
        }
        public string RequestId { get; private set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public string Detail { get; private set; }
        public string Title { get; private set; }

        //I ADDED
        public int? StatusCode { get; private set; }

        //I SHOULDN'T NEED THIS PROPERTY
        public IExceptionHandlerFeature CurrentContext { get; private set; }
    }
}
