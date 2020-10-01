using IdManagement.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace IdManagement.Controllers
{
    [Route("{controller}/{action}")]
    public class ErrorController : Controller
    {
        public ErrorController() {}

        #region Actions for Middelware Error Handling 
        /// <summary>
        ///app.UseExceptionHandler("/Error"); Global unhandled error handler that returns message to UI.
        /// </summary>
        [Route("/error")]
        [AllowAnonymous]
        public IActionResult Error()
        {
            var error = HttpContext.Features.Get<IExceptionHandlerFeature>();

            if (error == null)
                return Redirect("~/Home/Index");
            
            ErrorViewModel errorResposne = BuildErrorResponse(error);
            HttpContext.Response.StatusCode = (int)errorResposne.StatusCode;

            return View("Error", errorResposne);
        }


        /// <summary>
        /// app.UseStatusCodePagesWithReExecute global error handling
        /// </summary>
        /// <param name="statusCode"></param>
        [HttpGet]
        [Route("/error/{:id}")]
        [AllowAnonymous]
        public IActionResult Error(int? statusCode = null)
        {
            if (statusCode < 399)
                return Redirect("~/Home/Index");

            int _statusCode = (int)statusCode;
            string title = null;
            string details = null;
            string emoji = null;

            switch (_statusCode)
            {
                case 400:
                    title = "Bad Request";
                    details = "Our helper Elves are telling us that you made a bad request.";
                    emoji = "&#128562;";
                    break;
                case 401:
                    title = "Unathorized";
                    details = "We are going to need you to sign in.";
                    emoji = "&#128563";
                    break;
                case 403:
                    //App will redirect to /Access/Denied
                    break;
                case 404:
                    title = "Not Found";
                    details = "Sorry, but our helper Elves weren't able to find that.";
                    emoji = "&#128533";
                    break;
                case 408:
                    title = "Request Timeout";
                    details = "Sorry, but our helper Elves couldn't get the trend mill up to speed, your request timed out.";
                    emoji = "&#128565";
                    break;
                case 501:
                    title = "Not Implemented";
                    details = "Our helper Elves aren't willing to preform that action for you.";
                    emoji = "&#128542";
                    break;
                default:
                    _statusCode = 500;
                    title = "Internal Server Error";
                    details = "A hiccup has occured, our helper Elves are looking into it.";
                    emoji = "&#128533";
                    break;
            }

            var evm = new ErrorViewModel(Activity.Current?.Id ?? HttpContext.TraceIdentifier, details, title, _statusCode, emoji);

            return View("Error", evm);
        }
        #endregion


        #region 
        private ErrorViewModel BuildErrorResponse(IExceptionHandlerFeature context)
        {
            IExceptionHandlerFeature _context = context;

            int code = 500;
            string detail = "A hiccup has occured, our helper Elves are looking into it.";
            string title = "An Internal Server Error has occurred";
            string emoji = "&#128533";

            ErrorViewModel response = new ErrorViewModel(Activity.Current?.Id ?? HttpContext.TraceIdentifier, detail, title, code, emoji);
       
            return response;
        }
        #endregion
    }
}