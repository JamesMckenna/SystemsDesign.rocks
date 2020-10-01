//https://github.com/IdentityServer/IdentityServer4.Demo/blob/main/src/IdentityServer4Demo/Api/TestController.cs
using System.Linq;
using IdentityServer4;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdApi.Controllers
{
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