using Microsoft.AspNetCore.Mvc.Filters;
using Serilog;

namespace IdManagement.Services.Logging
{
    //FROM Andrew Lock Blog about Serilog
    public class LoggingActionFilter : IActionFilter
    {
        private readonly IDiagnosticContext _diagnosticContext;
        public LoggingActionFilter(IDiagnosticContext diagnosticContext)
        {
            _diagnosticContext = diagnosticContext;
        }
        void IActionFilter.OnActionExecuted(ActionExecutedContext context){}

        void IActionFilter.OnActionExecuting(ActionExecutingContext context)
        {
            _diagnosticContext.Set("RouteData", context.ActionDescriptor.RouteValues);
            _diagnosticContext.Set("ActionName", context.ActionDescriptor.DisplayName);
            _diagnosticContext.Set("ActionId", context.ActionDescriptor.Id);
            _diagnosticContext.Set("ValidationState", context.ModelState.IsValid);
        }
    }
}
