using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
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
                _logger.LogError("Validation Error occurred. ModelState:{0}, Context:{1}", errors, context);


                //Builds a 'friendly' client side error message with errors
                context.Result = new BadRequestObjectResult(new ApiBadRequestResponse(context.ModelState));
            }
            base.OnActionExecuting(context);
        }
    }
}
