using System;
using System.Diagnostics;
using IdManagement.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Serilog;

namespace IdManagement.Controllers
{
    [ApiController]
    public class ErrorController : Controller
    {
        private readonly ILogger<ErrorController> _logger;
        private readonly IDiagnosticContext _diagnosticContext;
        public ErrorController(ILogger<ErrorController> logger, IDiagnosticContext diagnosticContext)
        {
            _logger = logger;
            _diagnosticContext = diagnosticContext; ;
        }

        [Route("/error")]
        [AllowAnonymous]
        public IActionResult Error()
        {
            //https: //docs.microsoft.com/en-us/dotnet/csharp/programming-guide/exceptions/creating-and-throwing-exceptions
            var error = HttpContext.Features.Get<IExceptionHandlerFeature>();

            if (error == null)
                return Redirect("~/Home/Index");

            ErrorViewModel errorResposne = BuildErrorResponse(error);
            HttpContext.Response.StatusCode = (int)errorResposne.StatusCode;

            _diagnosticContext.Set("CatalogLoadTime", 1423);
            return View("Error", errorResposne);
        }

        [Route("/Error/{0}")]
        [AllowAnonymous]
        public IActionResult Error([Bind(Prefix = "id")] int statusCode)
        {
            //ALWAYS NULL - Find out why
            //var statusCodeResult = HttpContext.Features.Get<IStatusCodeReExecuteFeature>();

            //ALWAYS NULL - Find out why and/or fix ErrorViewModel
            var error = HttpContext.Features.Get<IExceptionHandlerFeature>();

            statusCode = HttpContext.Response.StatusCode;
            string title = null;
            string details = null;
            
            //// Switch to the appropriate page - FIX THIS, NOT YET FINISHED AND DOESN'T HANDLE ALL STATUSCODE ERRORS
            switch (statusCode)
            {
                case 400:
                    title = "Bad Request";
                    details = "Our helper Elves are telling us that you made a bad request. (O.O)";
                    break;
                case 404:
                    title = "Not Found";
                    details = "Sorry, but our helper Elves couldn't find your request. \u00AF\u005C\u005F\u0028\u006F\u002E\u006F\u0029\u005F\u002F\u00AF";
                    break;
                case 500:
                    title = "Internal Server Error";
                    details = "A hiccup has occured, our helper Elves are looking into it. \u00AF\u005C\u005F\u0028\u006F\u002E\u006F\u0029\u005F\u002F\u00AF;";
                    break;
                case 0:
                    statusCode = 500;
                    title = "Internal Server Error";
                    details = "A hiccup has occured, our helper Elves are looking into it. \u00AF\u005C\u005F\u0028\u006F\u002E\u006F\u0029\u005F\u002F\u00AF;";
                    break;
            }

            var evm = new ErrorViewModel(Activity.Current?.Id ?? HttpContext.TraceIdentifier, details, title, statusCode, error);

            _diagnosticContext.Set("CatalogLoadTime", 1423);
            return View("Error", evm);
        }

        internal ErrorViewModel BuildErrorResponse(IExceptionHandlerFeature context)
        {

            /*************** FIX THIS / FINISH THIS ******************/

            IExceptionHandlerFeature _context = context;
            Exception exception = _context?.Error;
            int code = 500;
            string msg = "A hiccup has occured, our helper Elves are looking into it. \u00AF\u005C\u005F\u0028\u006F\u002E\u006F\u0029\u005F\u002F\u00AF;";
            string title = exception.Message;

            if (exception is AccessViolationException) 
            { 
                code = 401;
                msg = "I regret to say, but that was an Unauthorized Request. :( \n  Please Log In";
            }
            else if (exception is AggregateException) 
            { 
                code = 500;
                msg = "";
            }
            else if (exception is ApplicationException) 
            { 
                code = 500;
                msg = "";
            }
            else if (exception is ArgumentNullException) 
            { 
                code = 400;
                msg = "";
            }
            else if (exception is ArgumentOutOfRangeException) 
            { 
                code = 400;
                msg = "Some Message";
            }
            else if (exception is ArgumentException)
            {
                code = 400;
                msg = "";
            }
            else if (exception is ArithmeticException) 
            { 
                code = 400;
                msg = "";
            }
            else if (exception is DivideByZeroException) 
            { 
                code = 403;
                msg = "";
            }
            else if (exception is IndexOutOfRangeException) 
            { 
                code = 412;
                msg = "";
            }
            else if (exception is NullReferenceException) 
            {
                code = 412;
                msg = "";
            }
            else if (exception is OutOfMemoryException) 
            { 
                code = 500;
                msg = "";
            }
            else if (exception is SystemException) 
            { 
                code = 500;
                msg = "";
            }
            else if (exception is TimeoutException) 
            { 
                code = 504;
                msg = "Sorry, but our helper Elves couldn't get the trend mill up to speed, your request timed out. \u00AF\u005C\u005F\u0028\u006F\u002E\u006F\u0029\u005F\u002F\u00AF";
            }
            else if (exception is UnauthorizedAccessException) 
            { 
                code = 401;
                msg = "I regret to say, but that was an Unauthorized Request. :( \n  Please Log In";
            }
            else if (exception is Exception) 
            { 
                code = 500;
                msg = "";
            }

            ErrorViewModel response = new ErrorViewModel(Activity.Current?.Id ?? HttpContext.TraceIdentifier, msg, title, code, _context);
       
            return response;
        }
    }
}