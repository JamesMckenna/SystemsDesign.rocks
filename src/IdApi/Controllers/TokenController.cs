//https://github.com/IdentityServer/IdentityServer4.Demo/blob/main/src/IdentityServer4Demo/Api/TestController.cs
using System.Linq;
using IdentityServer4;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdApi.Controllers
{
    //ERROR HANDLING FOR NET CORE API's
    //https: //stackoverflow.com/questions/38630076/asp-net-core-web-api-exception-handling
    //https: //www.devtrends.co.uk/blog/handling-errors-in-asp.net-core-web-api

    //MAKE THIS API AN IDENTITY CORE APP
    //https: //stackoverflow.com/questions/43224177/how-to-add-asp-net-identity-to-asp-net-core-when-webapi-template-is-selected
    [ApiController]
    [Authorize(AuthenticationSchemes = IdentityServerConstants.LocalApi.AuthenticationScheme)]
    public class TokenController : ControllerBase
    {
        [Route("Token")]
        public IActionResult Get()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value });
            return new JsonResult(claims);
        }
        [Route("/Token/Healthz")]
        public IActionResult Healthz()
        {
            return Ok("Healthy");
        }
    }
}