using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdManagement.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //TODO: add logger if keeping this
        private async Task<string> GetRefreshToken()
        {
            string refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            if (String.IsNullOrEmpty(refreshToken))
            {
                throw new NullReferenceException("No Access Token found");
            }

            return refreshToken;
        }



        [AllowAnonymous]
        public IActionResult Index()
        {
            //ViewData["User"] = (HttpContext.User.Identity.IsAuthenticated) 
            //    ? "Hello: " + HttpContext.User.Claims.First(c => c.Type == "name").Value 
            //    : "You're not signed in?";

            //The Identity Model package for Identity Server 4 doesn't have silent renew functionality.
            //I can get all tokens including the refresh token. I can request a new authentication session with the refresh token, 
            //or the User can navigate to a new page and the session should be refreshed automatically. 
            //I need to find/code a way to refresh the User session without doing a hard refresh/page navigation or implement session state.
            //Save any form fields/User input to session state, prompt User to do a hard refresh and then reload any User input from session state. 

            var authCookie = HttpContext.Request.Cookies["IS4SDAC"];

            var refreshToken = "";
            if (HttpContext.User != null)
            {
                refreshToken = GetRefreshToken().Result;
            }
                     
            if (authCookie != null)
            {
                var protectionProvider = DataProtectionProvider.Create(new DirectoryInfo(_configuration["SECRETS_DIR"]),
                        options =>
                        {
                            options.SetApplicationName(_configuration["Properties:ApplicationName"]);
                        });

                var protector = protectionProvider.CreateProtector("CookieProtector");

                //Get the decrypted cookie as plain text
                UTF8Encoding specialUtf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);
                byte[] protectedBytes = Base64UrlTextEncoder.Decode(authCookie);
                byte[] plainBytes = protector.Unprotect(protectedBytes);
                string plainText = specialUtf8Encoding.GetString(plainBytes);


                //Get teh decrypted cookies as a Authentication Ticket
                TicketDataFormat ticketDataFormat = new TicketDataFormat(protector);
                AuthenticationTicket ticket = ticketDataFormat.Unprotect(authCookie);

                var expires  = ticket.Properties.ExpiresUtc;
                var now = DateTime.Now;
                TimeSpan offSet = expires.Value - now;
                //TempData["session"] = Math.Round(offSet.TotalSeconds, 0);
            }

            return View();
        }

        public IActionResult Privacy(string param)
        {
            return View("Privacy");
        }
    }
}

