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

namespace IdManagement.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        
        [AllowAnonymous]
        public IActionResult Index()
        {
            ViewData["User"] = (HttpContext.User.Identity.IsAuthenticated) 
                ? "Hello: " + HttpContext.User.Claims.First(c => c.Type == "name").Value 
                : "You're not signed in?";

            //Just to read cookies.....delete this at some point or add a controller action and page to render cookie values
            var authCookie = HttpContext.Request.Cookies["IS4SDAC"];

            if (authCookie != null)
            {
                var protectionProvider = DataProtectionProvider.Create(new DirectoryInfo(@"C:\Secrets\"),
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
            }

            return View();
        }

        public IActionResult Privacy(string param)
        {
            return View("Privacy");
        }
    }
}

