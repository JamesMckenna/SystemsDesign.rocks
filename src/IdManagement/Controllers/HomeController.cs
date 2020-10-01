using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;

namespace IdManagement.Controllers
{
    public class HomeController : Controller
    {
        public HomeController()
        {
        }
        
        [AllowAnonymous]
        public IActionResult Index()
        {
            ViewData["User"] = (HttpContext.User.Identity.IsAuthenticated) 
                ? "Hello: " + HttpContext.User.Claims.First(c => c.Type == "name").Value 
                : "You're not signed in?";
           
            return View();
        }

        public IActionResult Privacy(string param)
        {
            //return BadRequest();
            return View("Privacy");
        }

        public IActionResult Secure()
        {
            return View();
        }
    }
}

