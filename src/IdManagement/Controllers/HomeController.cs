using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Serilog;
using System;
using System.ComponentModel.DataAnnotations;

namespace IdManagement.Controllers
{
    public class HomeController : Controller
    {
        //https: //docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controllerbase?view=aspnetcore-3.1
        //https: //hamidmosalla.com/2017/03/29/asp-net-core-action-results-explained/
        private readonly ILogger<HomeController> _logger;
        private readonly IDiagnosticContext _diagnosticContext;
        public HomeController(ILogger<HomeController> logger, IDiagnosticContext diagnosticContext)
        {
            _logger = logger;
            _diagnosticContext = diagnosticContext; 
        }

        public IActionResult Index()
        {
            //Used to log info gotten from ActionExecutingContext
            _diagnosticContext.Set("Home/Index", 1423);
            return View();
        }

        public IActionResult Privacy(string param)
        {

            _diagnosticContext.Set("Home/Privacy", 1423);
            return View("Privacy");
        }

        public IActionResult Logout()
        {
            _diagnosticContext.Set("Home/Logout", 1423);
            return SignOut(AppConfig.COOKIE, AppConfig.OIDC);
        }

        public IActionResult Secure()
        {
            _diagnosticContext.Set("Home/Secure", 1423);
            return View();
        }

        public IActionResult FakeUnauthorized()
        {
            return Unauthorized();
        }

        public IActionResult FakeValidationProblem()
        {
            return ValidationProblem();
        }

        public IActionResult FakeForbid()
        {
            return Forbid();
        }
        public IActionResult FakeBadRequest()
        {
            return BadRequest();
        }

        public IActionResult FakeNotFound()
        {
            return NotFound();
        }

        public IActionResult FakeArgumentNullException([Required] string arg)
        {
            if (!ModelState.IsValid)
                throw new ArgumentNullException("arg", "The Argument passed can not be null.");

            //else do stuff

            return View("Index");
        }

        public IActionResult FakeArgumentOutOfRangeException([FromQuery]int numberLessThan10)
        {       
            if (numberLessThan10 > 10 || numberLessThan10 < 0)
                throw new ArgumentOutOfRangeException("numberLessThan10", numberLessThan10, "The argument passed can not be greater then 10 or less than 0.");
            
            //else do stuff

            return View("Index");
        }

        public IActionResult FakeArgumentException(string stringArg)
        {
            if(String.IsNullOrWhiteSpace(stringArg))
                throw new ArgumentException("The correct was not a string", stringArg);

            //else do stuff

            return View("Index");
        }
    }
}

