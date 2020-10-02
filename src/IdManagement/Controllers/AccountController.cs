using IdentityCommon;
using IdManagement.Models.AccountViewModels;
using IdManagement.Services.MessageService;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Mail;
using System.Threading.Tasks;

namespace IdManagement.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<AccountController> _logger;
        private IConfiguration _configuration;
        public AccountController(
            UserManager<ApplicationUser> userManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
            _configuration = configuration;
        }

        #region All Login and Logout is redirected to and handled by IS4
        /// <summary>
        /// All Login and Logout is redirected to and handled by IS4 
        /// </summary>
        [HttpGet]
        [AllowAnonymous]
        public async Task Login()
        {
            try
            {
                await HttpContext.ChallengeAsync("oidc", new AuthenticationProperties { RedirectUri = "/" });
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/Login - an error occurred with the ChallengeAsync: {0}", ex);
                throw;
            } 
        }

        [HttpGet]
        public async Task Logout()
        {
            try
            {
                await HttpContext.SignOutAsync("Cookies");
                await HttpContext.SignOutAsync("oidc");
            }
            catch(Exception ex)
            {
                _logger.LogError("~/Account/Logout - an error occurred with SignOutAsync: {0}", ex);
                throw;
            } 
        }

        [HttpGet]
        public async Task FrontChannelLogout(string sid)
        {
            _logger.LogInformation("~/Account/FrontChannelLogout(string) - was called.");

            if (String.IsNullOrWhiteSpace(sid))
            {
                _logger.LogError("~/Account/FrontChannelLogout(string) - IS4 Login Server did not provide an 'sid' for FrontChannelLoggout");
                throw new ArgumentNullException("IS4 Login Server did not provide an sid for FrontChannelLoggout.");
            }
                
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogError("~/Account/FrontChannelLogout(string) - User.Identity.IsAuthenticated is false, IS4 Login Server processed FrontChannelLoggout. WHY?");
            }

            var currentSid = User.FindFirst("sid")?.Value ?? "";
            if (!string.Equals(currentSid, sid, StringComparison.Ordinal))
            {
                _logger.LogError("~/Account/FrontChannelLogout(string) - User sid did not match sid from IS4 Login Server. WHY?");
                throw new Exception("User sid did not match sid from IS4 Login Server");
            }

            try
            {
                await HttpContext.SignOutAsync("Cookies");
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/FrontChannelLogout(string) - an error occurred with the SignOutAsync: {0}", ex);
                throw;
            }
        }

        [HttpPost]
        public async Task BackChannelLogout(string sid)
        {
            _logger.LogInformation("~/Account/BackChannelLogout(string) - was called.");

            if (String.IsNullOrWhiteSpace(sid))
            {
                _logger.LogError("~/Account/BackChannelLogout(string) - IS4 Login Server did not provide an 'sid' for BackChannelLoggout");
                throw new ArgumentNullException("IS4 Login Server did not provide an sid for BackChannelLoggout.");
            }

            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogError("~/Account/BackChannelLogout(string) - User.Identity.IsAuthenticated is false, IS4 Login Server processed BackChannelLoggout. WHY?");
            }

            var currentSid = User.FindFirst("sid")?.Value ?? "";
            if (string.Equals(currentSid, sid, StringComparison.Ordinal))
            {
                try
                {
                    await HttpContext.SignOutAsync("oidc");
                }
                catch (Exception ex)
                {
                    _logger.LogError("~/Account/BackChannelLogout(string) - an error occurred with the SignOutAsync: {0}", ex);
                    throw;
                }
            }
        }
        #endregion

        #region Register new user
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = new ApplicationUser { UserName = model.UserName, Email = model.Email };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                _logger.LogError("~/Account/Register(RegisterViewModel) - userManager could not create a new user.");
                throw new InvalidOperationException("An error occurred creating a user account.");
            }

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            if (String.IsNullOrWhiteSpace(code))
            {
                _logger.LogError("~/Account/Register(RegisterViewModel) - userManager could not generate an email confirmation token.");
                throw new InvalidOperationException("An error occurred creating an email confirmation link.");
            }

            var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);

            try
            {
                await _emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);
            }
            catch (SmtpException ex)
            {
                _logger.LogError("~/Account/Register(RegisterViewModel) - unable to send email confirmation link to email address provided by user when registering: {0}.", ex);
                throw;
            }

            _logger.LogInformation("A new User account was created with a password. Username: {0}, Email: {1}, Password: {3}", model.UserName, model.Email, model.Password);

            return RedirectToAction("HasRegistered", "Account");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult HasRegistered()
        {
            TempData["HasRegistered"] = "You have registered for an account and an email has been sent to the email address provided when you registered." +
                "\nPlease check your email in box and click the link to complete the registration process. After which, you can log in with your new account.";
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction(nameof(AccessDenied));
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogError("~/Account/ConfirmEmail(string, string) - userManager could not find user by id. Confirmation email link generation must not be configured correctly.");
                throw new ApplicationException("Unable to load user account information.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (!result.Succeeded)
            {
                _logger.LogError("~/Account/ConfirmEmail(string, string) - userManager could not confirm email.");
                throw new ApplicationException("An error occurred confirming your email address.");
            }

            return View();
        }
        #endregion

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
