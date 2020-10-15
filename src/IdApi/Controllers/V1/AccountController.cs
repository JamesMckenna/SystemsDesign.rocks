using IdApi.Contracts.V1;
using IdApi.Services.ErrorHelpers;
using IdentityCommon;
using IdentityCommon.V1.DTO;
using IdentityServer4;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace IdApi.Controllers.V1
{
    [ApiController]
    [Authorize(AuthenticationSchemes = IdentityServerConstants.LocalApi.AuthenticationScheme)]
    [ApiConventionType(typeof(DefaultApiConventions))]
    public class AccountController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AccountController> _logger;
        private readonly UrlEncoder _urlEncoder;



        public AccountController(IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            ILogger<AccountController> logger,
            UrlEncoder urlEncoder)
        {
            _configuration = configuration;
            _userManager = userManager;
            _logger = logger;
            _urlEncoder = urlEncoder;
        }




        #region User Account 
        [HttpGet(ApiRoutes.AccountRoutes.GetUserAccountAsync)]
        public async Task<IActionResult> GetUserAccountAsync([BindRequired, FromQuery] string id)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    _logger.LogError("~/Manager/GetUserAccountAsync(string id) - userManger unable to retieve {0}'s account information", id);
                    return NotFound(new ApiResponse(404,$"A User with {id} was not found."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/GetUserAccountAsync(string id) - UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            UserAccount responseObj = new UserAccount
            {
                Username = user.UserName,
                Email = user.Email,
                TwoFactor = user.TwoFactorEnabled,
                PhoneNumber = user.PhoneNumber,
                IsEmailConfirmed = user.EmailConfirmed
            };

            string response = JsonSerializer.Serialize<UserAccount>(responseObj);
            return Ok(response);
        }
        #endregion




        #region Register Account Actions
        [HttpGet(ApiRoutes.AccountRoutes.ValidUserNameAsync)]
        public async Task<IActionResult> ValidUserNameAsync([BindRequired, FromQuery] string userName)
        {
            try
            {
                ApplicationUser user = await _userManager.FindByNameAsync(userName);
                if(user != null)
                {
                    return Ok("true");
                }
                return Ok("false");
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/GetUserAccountAsync(string id) - UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }
        }

        [HttpGet(ApiRoutes.AccountRoutes.VaildUserEmailAsync)]
        public async Task<IActionResult> ValidUserEmailAsync([BindRequired, FromQuery] string email)
        {
            try
            {
                ApplicationUser user = await _userManager.FindByEmailAsync(email);
                if(user != null)
                {
                    return Ok("true");
                }
                return Ok("false");
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/GetUserAccountAsync(string id) - UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }
        }

        [HttpPost(ApiRoutes.AccountRoutes.RegisterAccountAsync)]
        public async Task<IActionResult> RegisterAccountAsync([FromBody] RegisterAccount model)
        {
            ApplicationUser user = new ApplicationUser { UserName = model.UserName, Email = model.Email };

            try
            {
                IdentityResult result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    string errors = BuildErrorString(result);
                    _logger.LogError("~/api/v1/RegisterAccount(RegisterAccount) - userManager failed to register new user. UserName:{0}, Email:{1}, Error{2}", model.UserName, model.Email, errors);
                    return StatusCode(500, new ApiResponse(500, "Failed to register new user"));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/RegisterAccountAsync(RegisterAccount) - UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            string code;
            try
            {
                code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                if (String.IsNullOrWhiteSpace(code))
                {
                    _logger.LogError("~/api/v1/RegisterAccount(RegisterAccount) - userManager could not generate an email confirmation token.");
                    return StatusCode(500, new ApiResponse(500, "An error occurred generating an email confirmation token."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/RegisterAccountAsync(RegisterAccount) - UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            ApplicationUser newUser;
            try
            {
                newUser = await _userManager.FindByEmailAsync(model.Email);
                if (newUser == null)
                {
                    _logger.LogError("~/Manager/RegisterAccountAsync(RegisterAccount) - userManger unable to retieve the new User account. New User UserName:{0}, new User Email:{1}", model.UserName, model.Email);
                    return NotFound(new ApiResponse(404, $"The new User Account was not found."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/RegisterAccountAsync(RegisterAccount) - UserManger encountered an error at newUser, FindByEmailAsync. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            string urlEncodedCode = EncodeUrlWebString(code);
            RegisterAccount responseObj = new RegisterAccount
            {
                Id = newUser.Id,
                UserName = newUser.UserName,
                Email = newUser.Email,
                UrlEncodedVerificationCode = urlEncodedCode,
            };

            string response = JsonSerializer.Serialize<RegisterAccount>(responseObj);
            return Ok(response);
        }

        [HttpGet(ApiRoutes.AccountRoutes.ConfirmEmailAsync)]
        public async Task<IActionResult> ConfirmEmailAsync([BindRequired, FromQuery] string userId, [BindRequired, FromQuery] string code)
        {
            string decodedCode = DecodeUrlWebString(code);

            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    _logger.LogError("~/Account/ConfirmEmail(string, string) - userManager could not find user by id. Confirmation email link generation must not be configured correctly.");
                    return NotFound(new ApiResponse(404,"Unable to load User account information."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/RegisterAccountAsync(RegisterAccount) - UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            try
            {
                IdentityResult result = await _userManager.ConfirmEmailAsync(user, decodedCode);
                if (!result.Succeeded)
                {
                    string errors = BuildErrorString(result);
                    _logger.LogError("~/Account/ConfirmEmail(string, string) - userManager could not confirm email :{0} for User Id:{1}. Error{2}", user.Email, user.Id, errors);
                    return StatusCode(409, new ApiResponse(409,"An error occurred confirming the email address. Token validation failed."));
                }
                return Ok("The email address has be confirmed, you have successfully created a new account.");
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/RegisterAccountAsync(RegisterAccount) - UserManger encountered an error at ConfirmEmailAsync. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }
        }
        #endregion




        #region Add/Remove Phone Number
        [HttpPost(ApiRoutes.AccountRoutes.AddPhoneNumberAsync)]
        public async Task<IActionResult> AddPhoneNumberAsync([FromBody] AddPhoneNumber model)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                {
                    _logger.LogError("~/Account/AddPhoneNumberAsync(AddPhoneNumber) - userManager unable to retrieve User Id:{0}'s information. This should have been a valid user.", model.Id);
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("!/Account/AddPhoneNumberAsync(AddPhoneNumber) - UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503,new ApiResponse(503, "Error connecting to the database."));
            }

            string code;
            try
            {
                code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, model.PhoneNumber);
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - userManager was not able to generate verification code for User Id:{0}. Error: {1}", model.Id, ex);
                throw;
            }

            AddPhoneNumber responseObj = new AddPhoneNumber
            {
                Id = user.Id,
                PhoneNumber = model.PhoneNumber,
                Code = code,
            };
            string response = JsonSerializer.Serialize<AddPhoneNumber>(responseObj);

            return Ok(response);
        }

        [HttpPost(ApiRoutes.AccountRoutes.VerifyPhoneNumberAsync)]
        public async Task<IActionResult> VerifyPhoneNumberAsync([FromBody] AddPhoneNumber model)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                {
                    _logger.LogError("~/Account/VerifyPhoneNumber(VerifyPhoneNumberViewModel) - userManager unable to retrieve User Id:{0}'s information. This should have been a valid user.", model.Id);
                    return Unauthorized();
                }
            }
            catch(Exception ex)
            {
                _logger.LogError("UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503,new ApiResponse(503,"Error connecting to the database."));
            }

            try
            {
                IdentityResult result = await _userManager.ChangePhoneNumberAsync(user, model.PhoneNumber, model.Code);
                if (!result.Succeeded)
                {
                    string errors = BuildErrorString(result);
                    _logger.LogError("~/Account/VerifyPhoneNumber(VerifyPhoneNumber) - userManager unable to add/change phone number for {0}'s account. Errors:{1}", user.Id, errors);
                    return StatusCode(400, new ApiResponse(400, "An error occurred while attempting to verifiy your phone number. Did you enter the correct Verification Code?"));
                }

                _logger.LogInformation("User id:{0} successfully verified thier phone number.", model.Id);
                return Ok("The phone number verification was a success");
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, new ApiResponse(503,"Error connecting to the database."));
            }
        }

        [HttpPost(ApiRoutes.AccountRoutes.RemovePhoneNumberAsync)]
        public async Task<IActionResult> RemovePhoneNumberAsync([FromQuery] string id)//MOVE THIS TO BODY
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    _logger.LogError("~/Account/AddPhoneNumber(AddPhoneNumber) - userManager unable to retrieve User Id:{0}'s information. This should have been a valid user.", id);
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503,new ApiResponse(503,"Error connecting to the database."));
            }

            try
            {
                IdentityResult result = await _userManager.SetPhoneNumberAsync(user, null);
                if (!result.Succeeded)
                {
                    string errors = BuildErrorString(result);
                    _logger.LogError("~/Account/RemovePhoneNumberAsync - and error occured removing a phone number from id:{0}'s account information. Errors:{1}", id, errors);
                    return StatusCode(500, new ApiResponse(500,"Error occurred removing User's phone number."));
                }
                return Ok("The phone number has been successfully removed from the account.");
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, new ApiResponse(500,"Error connecting to the database."));
            }
        }
        #endregion




        #region Logged in User Change Password 
        [HttpPost(ApiRoutes.AccountRoutes.ChangePasswordAsync)]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePassword model)
        {

            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                {
                    _logger.LogError("~/Account/ChangePasswordAsync(ChanagePassword) - userManager unable to retrieve id:{0}'s account information.", model.Id);
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, new ApiResponse(500,"Error connecting to the database."));
            }

            try
            {
                IdentityResult result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (!result.Succeeded)
                {
                    string errors = BuildErrorString(result);
                    _logger.LogError("~/Account/ChangePasswordAsync(ChanagePassword) - userManager unable to change password for id:{0}'s account. Errors:{1}", model.Id, errors);
                    return StatusCode(500,$"An error occurred changing the password for account.");
                }
                return Ok("The password for the account has been changed.");
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, new ApiResponse(503,"Error connecting to the database."));
            }
        }
        #endregion




        #region Forgot Password Reset
        [HttpPost(ApiRoutes.AccountRoutes.ForgotPasswordAsync)]
        public async Task<IActionResult> ForgotPasswordAsync([FromBody] ForgotPassword model)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByEmailAsync(model.Email);
                if(user == null)
                {
                    _logger.LogError("~/Account/ForgotPasswordAsync(ForgotPassword) - userManager unable to retrieve {0}'s account information.", model.Email);
                    return NotFound(new ApiResponse(404, $"A User with the email address {model.Email} was not found."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, new ApiResponse(503,"Error connecting to the database."));
            }

            try
            {
                bool emailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
                if (!emailConfirmed)
                {
                    _logger.LogError("~/Account/ForgotPasswordAsync(ForgotPassword) - User id:{0} didn't confirm thier email address but was still able to login. Check Identity options configuration", user.Id);
                    return Conflict(new ApiResponse(409,$"User Id:{user.Id} has not confirmed the email address '{model.Email}' associated with the account. The password will not be reset."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, new ApiResponse(503,"Error connecting to the database."));
            }

            try
            {
                string code = await _userManager.GeneratePasswordResetTokenAsync(user);
                if (String.IsNullOrWhiteSpace(code))
                {
                    _logger.LogError("~/Account/ForgotPasswordAsync(ForgotPassword) - userManager was not able to Generate Password ResetToken for user id:{0}.", user.Id);
                    return StatusCode(500,new ApiResponse(500,"An error occurred generating the password reset token."));
                }

                ForgotPassword responseObj = new ForgotPassword
                {
                    Email = user.Email,
                    Code = EncodeUrlWebString(code),
                };

                string response = JsonSerializer.Serialize<ForgotPassword>(responseObj);

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. Error:{0}", ex);
                return StatusCode(503,new ApiResponse(503,"Error connecting to the database."));
            }
        }

        [HttpPost(ApiRoutes.AccountRoutes.ResetPasswordAsync)]
        public async Task<IActionResult> ResetPasswordAsync([FromBody] ResetPassword model)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByEmailAsync(model.Email);
                if(user == null)
                {
                    _logger.LogError("~/Account/ResetPasswordAsync(ChangePassword) - An Error occurred attempting to find the User Id:{0}, for a forgot password reset.", model.Email);
                    return NotFound(new ApiResponse(404,"An Error occurred attempting reset the password on your account."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503,"Error connecting to the database."));
            }

            try
            {
                string code = DecodeUrlWebString(model.Code);
                IdentityResult result = await _userManager.ResetPasswordAsync(user, code, model.Password);
                if (!result.Succeeded)
                {
                    string errors = BuildErrorString(result);
                    _logger.LogError("~/Account/ResetPasswordAsync(ResetPassword) - userManager unable to reset password for {0}'s account information. Errors:{1}", user.Id, errors);
                    return StatusCode(403,new ApiResponse(403,$"An error occurred resetting the account password. Errors: {errors}"));
                }
                return Ok("Password has been successfully reset.");
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503,"Error connecting to the database."));
            }
        }
        #endregion



  
        #region Enable/Disable MFA
        [HttpGet(ApiRoutes.AccountRoutes.LoadSharedKeyAndQrCodeUriAsync)]
        public async Task<IActionResult> LoadSharedKeyAndQrCodeUriAsync([FromBody] string userId)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(userId);
                if(user == null)
                {
                    _logger.LogError("~/Account/LoadSharedKeyAndQrCodeUriAsync(userId) - Could not find User Id:{0}. Unable to generate shared key and QR codes.", userId);
                    return NotFound(new ApiResponse(404, $"~/Account/LoadSharedKeyAndQrCodeUriAsync(userId) - Could not find User Id:{userId}. Unable to generate shared key and QR codes."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            string unformattedKey;
            try
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);//reset Authenticator Key - there maybe a stale Authenticator Key from previous enable/disable 2fa
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);//For some reason, calling this method without calling ResetAuthenticatorKeyAsync first, returns null. Find time to understand why.
                if (String.IsNullOrWhiteSpace(unformattedKey))
                {
                    _logger.LogError("~/Account/LoadSharedKeyAndQrCodeUriAsync(userId) - _userManager encountered an error Getting Authenticator Key Async.");
                    return StatusCode(500, new ApiResponse(500, "An internal error occurred enabling Multi-Factor Authentication."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/LoadSharedKeyAndQrCodeUriAsync(userId) - UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            EnableAuthenticator responseObj = new EnableAuthenticator
            {
                SharedKey = FormatKey(unformattedKey),
                AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey),
            };

            string response = JsonSerializer.Serialize<EnableAuthenticator>(responseObj);
            return Ok(response);
        }

        [HttpPost(ApiRoutes.AccountRoutes.EnableAuthenticatorAsync)]
        public async Task<IActionResult> EnableAuthenticatorAsync([FromBody] EnableAuthenticator model)
        {

            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                {
                    _logger.LogError("~/Account/EnableAuthenticatorAsync(EnableAuthenticator) - Could not find User Id:{0}. Unable to generate shared key and QR codes.", model.Id);
                    return NotFound(new ApiResponse(404, $"~/Account/EnableAuthenticatorAsync(EnableAuthenticator) - Could not find User Id:{model.Id}. Unable to generate shared key and QR codes."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            try
            {
                //Clean any whitespace in model.Code
                string verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
                bool is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
                if (!is2faTokenValid)
                {
                    return StatusCode(400, new ApiResponse(400, "Verification code is invalid. Please scan the QR Code or enter the above Verification Code Key. Then use the One-Time password code generated by the Authenticator App to verify and complete 2FA set up."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            try
            {
                IdentityResult TwoFactorResult = await _userManager.SetTwoFactorEnabledAsync(user, true);
                if (!TwoFactorResult.Succeeded)
                {
                    string errors = BuildErrorString(TwoFactorResult);
                    _logger.LogError("~/Account/EnableAuthenticator(EnableAuthenticatorViewModel) - userManager could not SetTwoFactorEnabledAsync for id:{0}'s account. Error:{1}", model.Id, errors);
                    return StatusCode(500,new ApiResponse(500,"An error occurred setting 2FA for your account."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            IEnumerable<string> recoveryCodes;
            try
            {
                recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                if (!recoveryCodes.Any())
                {
                    _logger.LogError("~/Account/EnableAuthenticator(EnableAuthenticatorViewModel) - userManager could not GenerateNewTwoFactorRecoveryCodesAsync for id:{0}'s account.", model.Id);
                    return StatusCode(500, new ApiResponse(500,"An error occurred setting 2FA for your account."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            EnableAuthenticator responseObj = new EnableAuthenticator
            {
                Id = user.Id,
                AuthenticatorUri = model.AuthenticatorUri,
                Code = model.Code,
                SharedKey = model.SharedKey,
                RecoveryCodes = recoveryCodes.ToArray(),
            };

            string response = JsonSerializer.Serialize<EnableAuthenticator>(responseObj);
            return Ok(response);
        }

        [HttpPost(ApiRoutes.AccountRoutes.Disable2faAsync)]
        public async Task<IActionResult> Disable2faAsync([FromBody] string id)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    _logger.LogError("~/Account/EnableAuthenticatorAsync(EnableAuthenticator) - Could not find User Id:{0}. Unable to disable 2fa.", id);
                    return NotFound(new ApiResponse(404, $"~/Account/Disable2faAsync(string) - Could not find User Id:{id}. Unable to disable 2fa."));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            try
            {
                IdentityResult disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
                if (!disable2faResult.Succeeded)
                {
                    string errors = BuildErrorString(disable2faResult);
                    _logger.LogError("~/Account/Disable2faAsync - an error occurred disabling 2fa for user id:{0}. Error:{1}", id, errors);
                    return StatusCode(500, new ApiResponse(500,$"Unexpected error occurred disabling 2FA for user id:{id}."));
                }

                IdentityResult resetResult = await _userManager.ResetAuthenticatorKeyAsync(user);
                if (!resetResult.Succeeded)
                {
                    string errors = BuildErrorString(resetResult);
                    _logger.LogError($"~/Account/Disable2faAsync - An error occurred: userManger couldn't ResetAuthenticatorKeyAsync. Error:{errors}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error connecting to the database. Error:{0}", ex);
                return StatusCode(503, new ApiResponse(503, "Error connecting to the database."));
            }

            _logger.LogInformation("User id:{0} has disabled 2fa.", id);
            return Ok("2 factor authentication has been disabled for the account.");
        }
        #endregion




        #region Helper Methods
        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            if (String.IsNullOrWhiteSpace(email) || String.IsNullOrWhiteSpace(unformattedKey)) throw new ArgumentNullException();

            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            return string.Format(AuthenticatorUriFormat, _urlEncoder.Encode(_configuration["Properties:Domain"]), _urlEncoder.Encode(email), unformattedKey); 
        }

        private string FormatKey(string unformattedKey)
        {
            if (String.IsNullOrWhiteSpace(unformattedKey)) throw new ArgumentNullException();

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

        private string BuildErrorString(IdentityResult result)
        {
            if (result.Succeeded) return "No Errors";

            string errors = "";
            foreach (var e in result.Errors)
            {
                errors = e.Code + " " + e.Description;
            }
            return errors;
        }

        private string EncodeUrlWebString(string stringToEncode)
        {
            if (String.IsNullOrWhiteSpace(stringToEncode)) throw new ArgumentNullException();

            byte[] stringToBytes = Encoding.UTF8.GetBytes(stringToEncode);
            string encodedUrlWebString = WebEncoders.Base64UrlEncode(stringToBytes);
            return encodedUrlWebString;
        }

        private string DecodeUrlWebString(string stringToDecode)
        {
            if (String.IsNullOrWhiteSpace(stringToDecode)) throw new ArgumentNullException();

            byte[] decodeStringToBytes = WebEncoders.Base64UrlDecode(stringToDecode);
            string decodedString = Encoding.UTF8.GetString(decodeStringToBytes);
            return decodedString;
        }
        #endregion
    }
}

