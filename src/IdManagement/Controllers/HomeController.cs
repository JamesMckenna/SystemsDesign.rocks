using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Net.Http;

namespace IdManagement.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;

        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Index([FromQuery] string ut, [FromQuery] string idt)//ut = access token, idt = id_token from MainClient. There is probably a more secure way. Think on this as the appication evoles.
        {
            //Don't delete this Action or IndexView. Will probably need it once I implement Authorization Polices and Administrator Management. 

            //To notify User of session timeout and auto log out
            //The Identity Model package for Identity Server 4 doesn't have (or need, tokens refresh when auto for interactive clients) silent renew functionality.
            //I can get all tokens including the refresh token. I can request a new authentication session with the refresh token, 
            //or the User can navigate to a new page and the session should be refreshed automatically. 
            //I need to find/code a way to refresh the User session without doing a hard refresh/page navigation or implement session state.
            //Save any form fields/User input to session state, prompt User to do a hard refresh and then reload any User input from session state. 
            
            if (HttpContext.User != null && !String.IsNullOrWhiteSpace(ut) && !String.IsNullOrWhiteSpace(idt))
            {
                HttpContext.Session.SetString("UserAccessToken", ut);
                HttpContext.Session.SetString("UserIdToken", idt);
            }
            else
            {
                //Currently, this should not be hit. User has to be Authenticated [Authorize] to hit this Controller/Action
                //Currently User can only log in through MainClient.
                return LocalRedirect(_configuration["AppURLS:IdManagementBaseUrl"] + "/Account/Login");
            }

            //return View();
            return LocalRedirect("~/Account/Index");
        }

        [AllowAnonymous]
        [HttpGet]
        public IActionResult MainClient()
        {
            //Delete the session cookie when leaving IdManagement app, no need for browser to hold onto useless cookie.
            HttpContext.Response.Cookies?.Delete(_configuration["Properties:IdManagementSessionCookie"]);
            return Redirect(_configuration["AppURLS:MainClientBaseUrl"]);
        }

        [HttpGet]
        public IActionResult Privacy()
        {
            return View("Privacy");
        }
    }
}

