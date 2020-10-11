using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IdApi.Services.ErrorHelpers
{
    public class ApiBadRequestResponse : ApiResponse
    {
        public IEnumerable<string> Errors { get; }

        public ApiBadRequestResponse(ModelStateDictionary modelState) : base(400)
        {
            if (modelState.IsValid)
            {
                throw new ArgumentException("ApiBadRequestResponse - A valid ModelState was passed in. ApiBadRequestResponse should not handle valid ModelState.", nameof(modelState));
            }

            Errors = modelState.SelectMany(x => x.Value.Errors).Select(x => x.ErrorMessage).ToArray();
        }
    }
}
