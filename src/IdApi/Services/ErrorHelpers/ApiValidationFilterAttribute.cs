using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;

namespace IdApi.Services.ErrorHelpers
{
    public class ApiValidationFilterAttribute : ActionFilterAttribute
    {
        private ILogger<ApiValidationFilterAttribute> _logger;

        public ApiValidationFilterAttribute(ILogger<ApiValidationFilterAttribute> logger)
        {
            _logger = logger;
        }
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            if (!context.ModelState.IsValid)
            {
                //log original error message
                var errors = context.ModelState.Values.SelectMany(v => v.Errors).Select(m => m.ErrorMessage).ToList();
                //Supplimentary info
                PathString path = context.HttpContext.Request.Path;
                _logger.LogError("Validation Error occurred. ModelState:{0}, Path:{1}", errors, path);

                //Build a 'friendly & consistent' error message with errors to return to client
                context.Result = new BadRequestObjectResult(new ApiBadRequestResponse(context.ModelState));
            }
            base.OnActionExecuting(context);
        }
    }
}
