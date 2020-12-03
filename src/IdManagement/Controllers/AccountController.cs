using IdManagement.Models;
using IdManagement.Models.AccountViewModels;
using IdManagement.Services.MessageService;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Data;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace IdManagement.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly IEmailSender _emailSender;
        private readonly ILogger<AccountController> _logger;
        private readonly IConfiguration _configuration;
        private readonly ISmsSender _smsSender;
        private readonly IHttpClientFactory _httpClientFactory;

        public AccountController(
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IConfiguration configuration,
            ISmsSender smsSender,
            IHttpClientFactory httpClientFactory)
        {
            _emailSender = emailSender;
            _logger = logger;
            _configuration = configuration;
            _smsSender = smsSender;
            _httpClientFactory = httpClientFactory;
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
                await HttpContext.ChallengeAsync("oidc", new AuthenticationProperties { RedirectUri = "Home/Index" });
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
                await HttpContext.SignOutAsync("oidc");
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
                    await HttpContext.SignOutAsync("Cookies");
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

            using HttpClient client = _httpClientFactory.CreateClient(_configuration["ApplicationIds:IdManagementId"]);

            /******************** Not sure I like this implementation ********************/
            string userName;
            try
            {
                userName = await client.GetStringAsync($"api/v1/Account/ValidUserNameAsync?userName={model.UserName}");
                if (userName == "true")
                {
                    ModelState.AddModelError("Error", $"UserName {model.UserName} has been taken.");
                    return View(model);
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError("~/Account/Register(RegisterViewModel, returnUrl) - An error occurred communicating with IdApi. Error:{0}, Error Message{1}", ex, ex.Message);
                throw;//Do I have to throw? Can I not just log the error and then pass a User friendly message to the view?
            }

            string email;
            try
            {
                email = await client.GetStringAsync($"api/v1/Account/ValidUserEmailAsync?email={model.Email}");
                if (email == "true")
                {
                    ModelState.AddModelError("Error", $"Email {model.Email} has been taken.");
                    return View(model);
                }
            }
            catch(HttpRequestException ex)
            {
                _logger.LogError("~/Account/Register(RegisterViewModel, returnUrl) - An error occurred communicating with IdApi. Error:{0}, Error Message{1}", ex, ex.Message);
                throw;
            }
            /******************** Not sure I like this implementation ********************/

            RegisterAccount registerAccount = new RegisterAccount
            {
                UserName = model.UserName,
                Email = model.Email,
                Password = model.Password
            };
            string asJson = JsonSerializer.Serialize<RegisterAccount>(registerAccount);
            var content = new StringContent(asJson, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("/api/v1/Account/RegisterAccountAsync", content);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("~/Account/Register(RegisterViewModel) - PostAsync could not complete request.");
                throw new ApplicationException();
            }

            string responseContent = await response.Content.ReadAsStringAsync();
            RegisterAccount registerResponse = JsonSerializer.Deserialize<RegisterAccount>(responseContent);
            response.EnsureSuccessStatusCode();

            var callbackUrl = Url.EmailConfirmationLink(registerResponse.Id, registerResponse.UrlEncodedVerificationCode, Request.Scheme);
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
                "\nPlease check your email in box / junk box and click the link to complete the registration process. After which, you can log in with your new account.";
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

            using HttpClient client = _httpClientFactory.CreateClient(_configuration["ApplicationIds:IdManagementId"]);
            HttpResponseMessage response = await client.GetAsync($"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/ConfirmEmailAsync?userId={userId}&code={code}");


            response.EnsureSuccessStatusCode();
            
            _logger.LogInformation("~/Account/ConfirmEmail - A new User has successfully confirmed thier email. User Id{0}", userId);

            return View();
        }
        #endregion




        #region Display Logged In User's current account settings
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var id = User?.FindFirstValue("sub");
            if(id == null)
            {
                _logger.LogError("~/Account/Index A User that was not logged in, somehow navigated to Account Manage page. HttpContext:{0}", HttpContext);
                return Forbid();
            }

            HttpResponseMessage response = await client.GetAsync($"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/GetUserAccount?id={id}");
            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                _logger.LogError("~/Account/Index - Error from IdApi - Bad Response Content:{0}", badResponse);
                throw new ApplicationException("There was an error retrieving the User Account information.");
            }

            var content = await response.Content.ReadAsStringAsync();
            IndexViewModel model = JsonSerializer.Deserialize<IndexViewModel>(content);
            response.EnsureSuccessStatusCode();

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
            if (!ModelState.IsValid) return View(model);

            string id = User?.FindFirstValue("sub");

            if (String.IsNullOrWhiteSpace(id))
            {
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - Unable to retrieve User ID from HttpContext User Principle. A User needs to be logged in in order to hit this endpoint.");
                throw new InvalidOperationException();
            }

            model.Id = id;
            string accessToken = await GetAccessToken();

            string content = JsonSerializer.Serialize<AddPhoneNumberViewModel>(model);

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
         
            StringContent requestContent = new StringContent(content, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage(HttpMethod.Post, $"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/AddPhoneNumberAsync") { Content = requestContent };

            using HttpResponseMessage response = await client.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - Error from IdApi - {0}", badResponse);
                TempData["ErrorMessage"] = "An Error has occurred attempting to save the phone number to your account.";
                return RedirectToAction(nameof(Index));
            }

            string phoneVerificationCode = await response.Content.ReadAsStringAsync();
            AddPhoneNumberViewModel phoneVerificationCodeObj = JsonSerializer.Deserialize<AddPhoneNumberViewModel>(phoneVerificationCode);
            response.EnsureSuccessStatusCode();

            await _smsSender.SendSmsAsync(phoneVerificationCodeObj.PhoneNumber, "Your phone verification security code is: " + phoneVerificationCodeObj.Code);
            TempData["PhoneNumber"] = phoneVerificationCodeObj.PhoneNumber;
                
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
            
            //Store phone number to re-display page if incorrect validation code was entered.
            TempData["phoneNumber"] = model.PhoneNumber;

            model.Id = id;
            string accessToken = await GetAccessToken();

            string content = JsonSerializer.Serialize<VerifyPhoneNumberViewModel>(model);

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            StringContent requestContent = new StringContent(content, Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage(HttpMethod.Post, $"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/VerifyPhoneNumberAsync") { Content = requestContent };

            using HttpResponseMessage response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                _logger.LogError("~/Account/VerifyPhoneNumber(AddPhoneNumberViewModel) - Error from IdApi - {0}", badResponse);
                TempData["ErrorMessage"] = badResponse;
                model.PhoneNumber = TempData["phoneNumber"].ToString();
                return View(model);
            }
            response.EnsureSuccessStatusCode();

            TempData.Remove("phoneNumber");
            TempData["StatusMessage"] = "You have successfully verified your phone number";
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemovePhoneNumber()
        {
            var id = User?.FindFirstValue("sub");

            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/RemovePhoneNumberAsync?id={id}");

            using HttpResponseMessage response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                _logger.LogError("~/Account/RemovePhoneNumber(id) - Error from IdApi - {0}", badResponse);
                TempData["ErrorMessage"] = "An error occurred while removing the phone number from your account.";
                return RedirectToAction(nameof(Index));
            }
            response.EnsureSuccessStatusCode();

            TempData["StatusMessage"] = "The phone number has been removed from your account.";
            return RedirectToAction(nameof(Index));
        }
        #endregion




        #region When user is already logged in and wants to change password. Does not send out an email.
        /****************** START When user is already logged in and wants to change password **********************/
        [HttpGet]
        [Authorize]
        public IActionResult ChangePassword()
        {
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

            string id = User?.FindFirstValue("sub");

            ChangePassword passwordChanged = new ChangePassword
            {
                Id = id,
                OldPassword = model.OldPassword,
                NewPassword = model.NewPassword,
            };

            string asJson = JsonSerializer.Serialize<ChangePassword>(passwordChanged);
            StringContent content = new StringContent(asJson, Encoding.UTF8, "application/json");

            string accessToken = await GetAccessToken();

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using HttpResponseMessage response = await client.PostAsync($"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/ChangePasswordAsync",content);

            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                _logger.LogError("~/Account/ChangePasswordAsync - Error from IdApi - {0}", badResponse);
                TempData["ErrorMessage"] = "An error occurred while changing the password for your account.";
                return RedirectToAction(nameof(Index));
            }
            response.EnsureSuccessStatusCode();

            _logger.LogInformation("User id:{0} has changed their password successfully.", id);
            return RedirectToAction(nameof(PasswordChanged));
        }

        [HttpGet]
        public async Task<IActionResult> PasswordChanged()
        {
            string accessToken = null;
            try
            {
                accessToken = await HttpContext.GetTokenAsync("access_token");
            }
            catch(ApplicationException ex)
            {
                 _logger.LogError("~/Account/PasswordChanged - id_token was null. User has to be logged in to hit this endpoint; id_token should not be null. Error:{0}", ex);
                throw; 
            }

            //using HttpClient client = _httpClientFactory.CreateClient();
            //client.BaseAddress = new Uri(_configuration["AppURLS:IS4BaseUrl"]);

            //var prop = new AuthenticationProperties { RedirectUri = _configuration["AppURLS:IdManagementBaseUrl"] + "/Account/ResetPasswordConfirmation" };
            //prop.Items.Add("id_token_hint", accessToken);
            //prop.Items.Add("ClientId", _configuration["ApplicationIds:MainClient"]);
            //prop.Items.Add("ClientName", _configuration["ApplicationNames:MainClient"]);
            //prop.Items.Add("SessionId", sessionCookie);
            //prop.Items.Add("logoutId", idToken);
            //await HttpContext.SignOutAsync("Cookies");
            //await HttpContext.SignOutAsync("oidc", prop);

            await HttpContext.SignOutAsync("Cookies");
            await HttpContext.SignOutAsync("oidc");

            return RedirectToAction(nameof(ResetPasswordConfirmation));
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

            using HttpClient client = _httpClientFactory.CreateClient(_configuration["ApplicationIds:IdManagementId"]);
            client.BaseAddress = new Uri(_configuration["AppURLS:IdApiBaseUrl"]);

            string asJson = JsonSerializer.Serialize<ForgotPasswordViewModel>(model);
            StringContent content = new StringContent(asJson, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync("/api/v1/Account/ForgotPasswordAsync", content);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("~/Account/ForgotPassword(ForgotPasswordViewModel) - An error occurred with the Http Response Message. Response:{0}", response);
                throw new HttpRequestException($"An error occurred attempting to reset the password on the account with the email address: {model.Email}");
            }

            string responseContent = await response.Content.ReadAsStringAsync();
            ResetPassword forgotPasswordObj = JsonSerializer.Deserialize<ResetPassword>(responseContent);
            response.EnsureSuccessStatusCode();

            var callbackUrl = Url.ResetPasswordCallbackLink(forgotPasswordObj.Code, Request.Scheme);

            try
            {
                await _emailSender.SendEmailAsync(model.Email, "Reset Your Password", $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
            }
            catch (SmtpException ex)
            {
                _logger.LogError("An error occurred sending Password reset email for User Email:{0}, Error:{1}, Error Message{2}, Stack Trace:{3}", forgotPasswordObj.Email, ex, ex.Message, ex.StackTrace);
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
        public IActionResult ResetPassword([FromQuery] string code)
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

            ResetPassword resetPassword = new ResetPassword
            {
                Email = model.Email,
                Code = model.Code,
                Password = model.Password,
            };

            using HttpClient client = _httpClientFactory.CreateClient(_configuration["ApplicationIds:IdManagementId"]);
            client.BaseAddress = new Uri(_configuration["AppURLS:IdApiBaseUrl"]);

            string asJson = JsonSerializer.Serialize<ResetPassword>(resetPassword);
            StringContent content = new StringContent(asJson, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync("/api/v1/Account/ResetPasswordAsync", content);
            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                ResponsePayload badResponseObj = JsonSerializer.Deserialize<ResponsePayload>(badResponse);
                _logger.LogError("~/Account/ResetPassword(ResetPasswordViewModel) - Error from IdApi - An Error occurred resetting the account password. StatusCode:{0}, Error Message:{1}", badResponseObj.StatusCode, badResponseObj.Message);
                return Redirect(_configuration["AppURLS:PublicError"] + $"?statusCode={badResponseObj.StatusCode}");
            }
            response.EnsureSuccessStatusCode();

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
        public IActionResult Disable2faWarning()
        {
            return View(nameof(Disable2fa));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2fa()
        {
            var id = User?.FindFirstValue("sub");

            string accessToken = await GetAccessToken();

            string asJson = JsonSerializer.Serialize<string>(id);
            StringContent content = new StringContent(asJson, Encoding.UTF8, "application/json");

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/Disable2faAsync") { Content = content };
            using HttpResponseMessage response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                _logger.LogError("~/Account/EnableAuthenticator - Error from IdApi - {0}", badResponse);
                TempData["ErrorMessage"] = "An error occurred while disabling 2 factor authentication on your account.";
                return RedirectToAction(nameof(Index));
            }
            response.EnsureSuccessStatusCode();

            TempData["StatusMessage"] = "You have disabled two factor authentication. 2FA can be re-enabled at anytime.";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string id = User?.FindFirstValue("sub");

            string accessToken = await GetAccessToken();

            string asJson = JsonSerializer.Serialize<string>(id);
            StringContent content = new StringContent(asJson, Encoding.UTF8, "application/json");

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/LoadSharedKeyAndQrCodeUriAsync") { Content = content };
            using HttpResponseMessage response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();/********************  LOOK AT THIS, NOT FINISHED        *****************/
                _logger.LogError("~/Account/EnableAuthenticator - Error from IdApi - {0}", badResponse);
                TempData["ErrorMessage"] = "An error occurred while setting up your account for 2 factor authentication.";
                return RedirectToAction(nameof(Index));
            }

            string responseObj = await response.Content.ReadAsStringAsync();
            EnableAuthenticatorViewModel model = JsonSerializer.Deserialize<EnableAuthenticatorViewModel>(responseObj);
            response.EnsureSuccessStatusCode();

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
        {

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var id = User?.FindFirstValue("sub");

            string accessToken = await GetAccessToken();

            EnableAuthenticator contentModel = new EnableAuthenticator
            {
                Id = id,
                AuthenticatorUri = model.AuthenticatorUri,
                Code = model.Code,
                SharedKey = model.SharedKey,
            };

            string asJson = JsonSerializer.Serialize<EnableAuthenticator>(contentModel);
            StringContent content = new StringContent(asJson, Encoding.UTF8, "application/json");

            HttpClient client = _httpClientFactory.CreateClient("IdApiAccount");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"{_configuration["AppURLS:IdApiBaseUrl"]}/api/v1/Account/EnableAuthenticatorAsync") { Content = content };
            using HttpResponseMessage response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                string badResponse = await response.Content.ReadAsStringAsync();
                ResponsePayload badResponseObj = JsonSerializer.Deserialize<ResponsePayload>(badResponse);
                if (badResponseObj.StatusCode == 400)
                {
                    ModelState.AddModelError("Code", "Verification code is invalid. Please scan the QR Code or enter the above Verification Code Key. Then use the One-Time password code generated by the Authenticator App to verify and complete 2FA set up.");
                    return View(model);
                }

                _logger.LogError("~/Account/EnableAuthenticator(EnableAuthenticatorViewModel) - Error from IdApi - {0}", badResponseObj);
                TempData["ErrorMessage"] = "An error occurred while setting up your account for 2 factor authentication.";
                return RedirectToAction(nameof(Index));
            }

            string responseObj = await response.Content.ReadAsStringAsync();
            EnableAuthenticatorViewModel responseModel = JsonSerializer.Deserialize<EnableAuthenticatorViewModel>(responseObj);
            response.EnsureSuccessStatusCode();

            _logger.LogInformation("User with id:{0} has enabled 2FA with an authenticator app.", id);

            return View("ShowCodes", responseModel);
        }
        #endregion




        /// <summary>
        /// Get User's access_token - consider doing something else with this as the more Controllers added to app, the more I need to dupicate this code (violates DRY)
        /// </summary>
        private async Task<string> GetAccessToken()
        {
            string accessToken = await HttpContext.GetTokenAsync("access_token");
   
            if (String.IsNullOrEmpty(accessToken))
            {
                _logger.LogError("~/Account/GetAccessToken - Access token could not be retieved.");
                throw new NullReferenceException("No Access Token found");
            }

            return accessToken;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
