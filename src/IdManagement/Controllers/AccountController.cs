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
using System.Linq;
using System.Net.Http;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;

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
        private readonly ISmsSender _smsSender;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly UrlEncoder _urlEncoder;
        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        private const string RecoveryCodesKey = nameof(RecoveryCodesKey);

        public AccountController(
            UserManager<ApplicationUser> userManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IConfiguration configuration,
            ISmsSender smsSender,
            IHttpClientFactory httpClientFactory,
            UrlEncoder urlEncoder
            )
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
            _configuration = configuration;
            _smsSender = smsSender;
            _httpClientFactory = httpClientFactory;
            _urlEncoder = urlEncoder;
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






        #region Display Logged In User's current account options/settings
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/Index - userManger unable to retieve {0}'s account information", id);
                throw new ApplicationException($"Unable to load user data.");
            }

            var model = new IndexViewModel
            {
                Username = user.UserName,
                Email = user.Email,
                TwoFactor = user.TwoFactorEnabled,
                PhoneNumber = user.PhoneNumber,
                IsEmailConfirmed = user.EmailConfirmed,
            };

            return View(model);
        }
        #endregion







        #region Add/Remove Phone Number
        [HttpGet]
        public IActionResult PhoneNumber()
        {
            return View(nameof(PhoneNumber));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> PhoneNumber(AddPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "A phone number needs to be entered.");
                return View(model);
            }

            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - userManager unable to retrieve {0}'s information.");
                throw new InvalidOperationException("An error occurred retieving your account information.");
            }

            var code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);
            if (code == null)
            {
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - userManager was not able to generate verification code.");
                throw new InvalidOperationException("An error occurred generating the verification code.");
            }

            try
            {
                await _smsSender.SendSmsAsync(model.PhoneNumber, "Your phone verification security code is: " + code);
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - An error occurred sending sms verification code. {0}", ex);
                throw;
            }

            TempData["PhoneNumber"] = model.PhoneNumber;
            return RedirectToAction(nameof(VerifyPhoneNumber));
        }

        [HttpGet]
        public IActionResult VerifyPhoneNumber()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Phone number verification failed. Did you enter the code incorrectly?");
                return View(model);
            }

            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/VerifyPhoneNumber(VerifyPhoneNumberViewModel) - userManager unable to retrieve {0}'s information.");
                throw new InvalidOperationException("An error occurred retieving your account information.");
            }

            var result = await _userManager.ChangePhoneNumberAsync(user, model.PhoneNumber, model.Code);
            if (!result.Succeeded)
            {
                _logger.LogError("~/Account/VerifyPhoneNumber(VerifyPhoneNumberViewModel) - userManager unable to change phone number for {0}'s account.");
                throw new InvalidOperationException("An error occurred changing the phone number listed on your account.");
            }

            TempData["StatusMessage"] = "You have successfully verified your phone number";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemovePhoneNumber()
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/RemovePhoneNumber - userManager unable to retrieve id:{0}'s account information.", id);
                throw new ApplicationException($"Unable to load user information.");
            }

            var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, null);
            if (!setPhoneResult.Succeeded)
            {
                _logger.LogError("~/Account/RemovePhoneNumber - and error occured removing a phone number from id:{0}'s account information.", id);
                throw new ApplicationException($"Unexpected error occurred removing the phone number.");
            }

            TempData["StatusMessage"] = "The phone number has been removed from your account.";
            return RedirectToAction(nameof(Index));
        }
        #endregion




        #region When user is already logged in and wants to change password 
        /****************** START When user is already logged in and wants to change password **********************/
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> ChangePassword()
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/ChangePassword - userManager unable to retrieve id:{0}'s account information.", id);
                throw new ApplicationException($"Unable to load account information.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                _logger.LogError("~/Account/ChangePassword - userManager unable to retrieve id:{0}'s password.", id);
                throw new ApplicationException($"Unable to load account information.");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/ChangePassword(ChanagePasswordViewModel) - userManager unable to retrieve id:{0}'s account information.", id);
                throw new InvalidOperationException($"Unable to load user account information.");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                _logger.LogError("~/Account/ChangePassword(ChanagePasswordViewModel) - userManager unable to change password for id:{0}'s account.", id);
                throw new InvalidOperationException($"An error occurred changing the password for account.");
            }

            _logger.LogInformation("User id:{0} has changed their password successfully.", id);
            return RedirectToAction(nameof(PasswordChanged));
        }

        [HttpGet]
        public async Task<IActionResult> PasswordChanged()
        {
            //providing a id_token to /connect/endsession is supposed to disable Logout prompt screen. 
            //Running in Dev mode, prompt screen flashes briefly before redirecting to ResetPasswordConfirmation View
            string idToken = await HttpContext.GetTokenAsync("id_token");
            if (String.IsNullOrWhiteSpace(idToken))
            {
                _logger.LogError("~/Account/PasswordChanged - id_token was null. User has to be logged in to hit this endpoint; id_token should not be null.");
            }

            string toEncode = $"id_token_hint={idToken}&post_logout_redirect_uri=" + _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/PasswordChanged";
            string encoded = HttpUtility.UrlEncode(toEncode);

            HttpClient client = _httpClientFactory.CreateClient();
            client.BaseAddress = new Uri(_configuration["AppURLS:IS4BaseUrl"]);
            try
            {
                await client.GetAsync("/connect/endsession?" + encoded);
            }
            catch (UriFormatException ex)
            {
                _logger.LogError("~/Account/PasswordChanged() - Query string encoding error occurred. {0}", ex);
                throw;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("An error occurred when requesting /connect/endsession endpoint from IS4 server. {0}", ex);
                throw;
            }

            var prop = new AuthenticationProperties { RedirectUri = _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/ResetPasswordConfirmation" };

            return new SignOutResult(new[] { "oidc", "Cookies" }, prop);
        }
        /****************** FINSIHED When user is already logged in and wants to change password **********************/
        #endregion







        #region Forgot Password - Send out email to set new password
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogError("~/Account/ForgotPassword(ForgotPasswordViewModel) - userManager unable to retrieve {0}'s account information.", model.Email);
                throw new InvalidOperationException("An error occurred retrieving user account information.");
            }

            var emailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (!emailConfirmed)
            {
                _logger.LogError("~/Account/ForgotPassword(ForgotPasswordViewModel) - user id:{0} didn't confirm thier email address but was still able to login. Check Identity options configuration", user.Id);
                TempData["StatusMessage"] = "The email address for your account has not been confirmed. Please confirm your email so we can send you a password reset token.";
                return View();
            }

            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            if (String.IsNullOrWhiteSpace(code))
            {
                _logger.LogError("~/Account/ForgotPassword(ForgotPasswordViewModel) - userManager was not able to Generate Password ResetToken for user id:{0}.", user.Id);
                throw new InvalidOperationException("An error occurred generating the password reset token.");
            }

            var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);

            try
            {
                await _emailSender.SendEmailAsync(model.Email, "Reset Your Password", $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
            }
            catch (SmtpException ex)
            {
                _logger.LogError("An error occurred sending Password reset email for user id:{0}: {1}", user.Id, ex.StackTrace);
                throw;
            }

            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
            {
                _logger.LogError("~/Account/ResetPassword(string) - ResetPassword code was null.");
                throw new ArgumentNullException("A code must be supplied for password reset.");
            }
            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogError("~/Account/ResetPassword(ResetPasswordViewModel) - userManager unable to retrieve {0}'s account information.");
                throw new InvalidOperationException("An error occurred retrieving user account information.");
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (!result.Succeeded)
            {
                _logger.LogError("~/Account/ResetPassword(ResetPasswordViewModel) - userManager unable to reset password for {0}'s account information.");
                throw new InvalidOperationException("An error occurred resetting the account password.");
            }

            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }
        #endregion





        #region MFA - Enable and Disable Only, LoginWith2FA part of IS4 responsibilty
        [HttpGet]
        public async Task<IActionResult> Disable2faWarning()
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/Disable2fWarning - userManager unable to retrieve id:{0}'s account information.", id);
                throw new InvalidOperationException($"Unable to load account information.");
            }

            if (!user.TwoFactorEnabled)
            {
                _logger.LogError("~/Account/Disable2faWarning - an error occurred disabling 2fa for user id:{0}. 2FA was returned as false. User should not have been able to hit this endpoint.", id);
                throw new InvalidOperationException($"Unexpected error occurred disabling 2FA.");
            }
            return View(nameof(Disable2fa));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2fa()
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/Disable2fa - userManager could not retrieve id:{0}'s account information.", id);
                throw new InvalidOperationException($"Unable to load user information.");
            }

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                _logger.LogError("~/Account/Disable2fa - an error occurred disabling 2fa for user id:{0}.", id);
                throw new InvalidOperationException($"Unexpected error occurred disabling 2FA for user id:{id}.");
            }

            _logger.LogInformation("User with email id:{0} has disabled 2fa.", id);

            //Overwrite current AuthenticationKey incase it somehow made it into evil hands. If/when user re-enables 2FA, a new AuthenticationKey will be created and used.
            var resetResult = await _userManager.ResetAuthenticatorKeyAsync(user);
            if (!resetResult.Succeeded)
            {
                //In this case an Error does not need to be thrown. But log so developer knows something went wrong.
                _logger.LogError("~/Account/Disable2fa - An error occurred: userManger couldn't ResetAuthenticatorKeyAsync");
            }

            TempData["StatusMessage"] = "You have disabled two factor authentication. 2FA can be re-enabled at anytime.";
            var vm = BuildIndexViewModel(user);
            return RedirectToAction(nameof(Index), vm);
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/EnableAuthenticator - userManager could not get account information for user id:{0}", id);
                throw new InvalidOperationException($"Unable to load user information.");
            }

            var model = new EnableAuthenticatorViewModel();
            await LoadSharedKeyAndQrCodeUriAsync(user, model);

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
        {
            var id = User?.FindFirstValue("sub");
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Account/EnableAuthenticator(EnableAuthenticatorViewModel) - userManager could not retrieve id:{0}'s account information", id);
                throw new InvalidOperationException($"Unable to load user information.");
            }

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (!is2faTokenValid)
            {
                ModelState.AddModelError("Code", "Verification code is invalid. Please scan the QR Code or enter the above Verification Code Key. Then use the One-Time password code generated by the Authenticator App to verify and complete 2FA set up.");
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            var TwoFactorResult = await _userManager.SetTwoFactorEnabledAsync(user, true);
            if (!TwoFactorResult.Succeeded)
            {
                _logger.LogError("~/Account/EnableAuthenticator(EnableAuthenticatorViewModel) - userManager could not set 2fa for id:{0}'s account.", id);
                throw new InvalidOperationException($"An error occurred setting 2FA for your account.");
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            if (!recoveryCodes.Any())
            {
                _logger.LogError("~/Account/EnableAuthenticator(EnableAuthenticatorViewModel) - userManager could not generate 2fa recovery codes for id:{0}'s account.", id);
                throw new InvalidOperationException("An error occurred setting 2FA for your account.");
            }

            var vm = new EnableAuthenticatorViewModel
            {
                Code = model.Code,
                SharedKey = model.SharedKey,
                AuthenticatorUri = model.AuthenticatorUri,
                RecoveryCodes = recoveryCodes.ToArray()
            };
            //TempData["AuthCodes"] = JsonConvert.SerializeObject(vm);
            TempData["AuthCodes"] = JsonSerializer.Serialize<EnableAuthenticatorViewModel>(vm);
            _logger.LogInformation("User with id:{0} has enabled 2FA with an authenticator app.", id);

            return RedirectToAction(nameof(ShowCodes));
        }

        [HttpGet]
        public async Task<IActionResult> ShowCodes()
        {
            EnableAuthenticatorViewModel model;

            if (TempData.ContainsKey("AuthCodes"))
            {
                _ = new EnableAuthenticatorViewModel();
                //model = JsonConvert.DeserializeObject<EnableAuthenticatorViewModel>(TempData["AuthCodes"].ToString());
                model = JsonSerializer.Deserialize<EnableAuthenticatorViewModel>(TempData["AuthCodes"].ToString());
                TempData["StatusMessage"] = "You have successfully added Two Factor Authentication to your account.";
            }
            else
            {
                var id = User?.FindFirstValue("sub");
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    _logger.LogError("~/Account/ShowCodes - userManager could not retrieve id:{0}'s account information", id);
                    throw new ApplicationException($"Unable to load account information.");
                }

                var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
                if (!disable2faResult.Succeeded)
                {
                    _logger.LogError("~/Account/ShowCodes - an error occurred disabling 2fa for user id:{0}.", id);
                }

                var resetResult = await _userManager.ResetAuthenticatorKeyAsync(user);
                if (!resetResult.Succeeded)
                {
                    _logger.LogError("~/AccountShowCodes - An error occurred: userManger couldn't ResetAuthenticatorKeyAsync");
                }

                _logger.LogError("~/Account/ShowCodes - An error occurred displaying Auth recovery codes to user id:{0}", id);
                throw new ApplicationException("An error occurred showing 2FA Authentication Codes. Please try setting up 2FA again.");
            }

            return View(model);
        }
        #endregion


        #region Helpers
        private IndexViewModel BuildIndexViewModel(ApplicationUser appilcationUser)
        {
            IndexViewModel indexViewModel = new IndexViewModel
            {
                TwoFactor = appilcationUser.TwoFactorEnabled,
                Username = appilcationUser.UserName,
                Email = appilcationUser.Email,
                PhoneNumber = appilcationUser.PhoneNumber
            };
            return indexViewModel;
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }
            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                _urlEncoder.Encode("IdentityManagement"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }

        private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, EnableAuthenticatorViewModel model)
        {
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = FormatKey(unformattedKey);
            model.AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey);
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
