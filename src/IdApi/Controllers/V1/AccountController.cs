using IdApi.Contracts.V1;
using IdentityCommon;
using IdentityCommon.V1.DTO;
using IdentityServer4;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace IdApi.Controllers.V1
{
    [ApiController]
    [Authorize(AuthenticationSchemes = IdentityServerConstants.LocalApi.AuthenticationScheme)]
    [ApiConventionType(typeof(DefaultApiConventions))]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(UserManager<ApplicationUser> userManager, ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet(ApiRoutes.AccountRoutes.Index)]
        public IActionResult Index()
        {
            string test = "You have hit the IdApi Manage Index endpoint.";
            return Ok(test);
        }

        #region User Account 
        [HttpGet(ApiRoutes.AccountRoutes.GetUserAccountAsync)]
        public async Task<IActionResult> GetUserAccountAsync([FromQuery] string id)
        {
            if (String.IsNullOrWhiteSpace(id))
            {
                _logger.LogError("~/ManageAccount/GetUserAccount(id) - Id parameter was null");
                return BadRequest();
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogError("~/Manager/GetUserAccount(id) - userManger unable to retieve {0}'s account information", id);
                return NotFound();
            }

            UserAccount userAccount = new UserAccount
            {
                Username = user.UserName,
                Email = user.Email,
                TwoFactor = user.TwoFactorEnabled,
                PhoneNumber = user.PhoneNumber,
                IsEmailConfirmed = user.EmailConfirmed
            };

            var response = JsonSerializer.Serialize<UserAccount>(userAccount);

            return Ok(response);
        }
        #endregion

        #region Register Account Actions
        [HttpGet(ApiRoutes.AccountRoutes.ValidUserNameAsync)]
        public async Task<string> ValidUserNameAsync([FromQuery] string userName)
        {
            if (String.IsNullOrWhiteSpace(userName)) throw new NullReferenceException();

            ApplicationUser user = await _userManager.FindByNameAsync(userName);
            bool response = (user == null);
            return JsonSerializer.Serialize(response);
        }

        [HttpGet(ApiRoutes.AccountRoutes.VaildUserEmailAsync)]
        public async Task<string> ValidUserEmailAsync([FromQuery] string email)
        {
            if (String.IsNullOrWhiteSpace(email)) throw new NullReferenceException();

            ApplicationUser user = await _userManager.FindByEmailAsync(email);
            bool response = (user == null);
            return JsonSerializer.Serialize(response);
        }

        [HttpPost(ApiRoutes.AccountRoutes.RegisterAccountAsync)]
        public async Task<IActionResult> RegisterAccountAsync([FromBody] RegisterAccount registerAccount)
        {
            if (registerAccount == null) throw new NullReferenceException();

            ApplicationUser user = new ApplicationUser { UserName = registerAccount.UserName, Email = registerAccount.Email };
            IdentityResult result = await _userManager.CreateAsync(user, registerAccount.Password);
            if (!result.Succeeded)
            {
                _logger.LogError("~/api/v1/RegisterAccount(RegisterAccount) - userManager could not register new user.");
                throw new ApplicationException("An error occurred creating an email confirmation link.");
            }

            string code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            if (String.IsNullOrWhiteSpace(code))
            {
                _logger.LogError("~/api/v1/RegisterAccount(RegisterAccount) - userManager could not generate an email confirmation token.");
                throw new ApplicationException("An error occurred creating an email confirmation link.");
            }
            string urlEncodedCode = EncodeUrlWebString(code);


            ApplicationUser newUser = await _userManager.FindByEmailAsync(registerAccount.Email);
            RegisterAccountResponse registerAccountResponse = new RegisterAccountResponse
            {
                Id = newUser.Id,
                UserName = newUser.UserName,
                Email = newUser.Email,
                UrlEncodedVerificationCode = urlEncodedCode,
            };

            string response = JsonSerializer.Serialize<RegisterAccountResponse>(registerAccountResponse);

            return Ok(response);
        }

        [HttpGet(ApiRoutes.AccountRoutes.ConfirmEmailAsync)]
        public async Task<IActionResult> ConfirmEmailAsync([FromQuery] string userId, [FromQuery] string code)
        {
            if (String.IsNullOrEmpty(userId) || String.IsNullOrWhiteSpace(code)) return BadRequest();

            string decodedCode = DecodeUrlWebString(code);

            ApplicationUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogError("~/Account/ConfirmEmail(string, string) - userManager could not find user by id. Confirmation email link generation must not be configured correctly.");
                throw new ApplicationException("Unable to load user account information.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, decodedCode);
            if (!result.Succeeded)
            {
                _logger.LogError("~/Account/ConfirmEmail(string, string) - userManager could not confirm email.");
                throw new ApplicationException("An error occurred confirming your email address. Token validation failed.");
            }

            return Ok(result.Succeeded);
        }
        #endregion

        #region Add/Remove Phone Number
        [HttpPost(ApiRoutes.AccountRoutes.AddPhoneNumberAsync)]
        public async Task<IActionResult> AddPhoneNumberAsync([FromBody] AddPhoneNumber phoneNumber)
        {
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(phoneNumber.Id);
                if (user == null)
                {
                    _logger.LogError("~/Account/AddPhoneNumber(AddPhoneNumber) - userManager unable to retrieve User Id:{0}'s information. This should have been a valid user.", phoneNumber.Id);
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, "Error connecting to the database.");
            }

            string code;
            try
            {
                code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, phoneNumber.PhoneNumber);
            }
            catch (Exception ex)
            {
                _logger.LogError("~/Account/PhoneNumber(AddPhoneNumberViewModel) - userManager was not able to generate verification code for User Id:{0}." +
                    "Error: {1}, Error Message: {2}", phoneNumber.Id, ex, ex.Message);
                throw;
            }

            AddPhoneNumber verificationCode = new AddPhoneNumber
            {
                Id = user.Id,
                PhoneNumber = phoneNumber.PhoneNumber,
                Code = code,
            };
            string response = JsonSerializer.Serialize<AddPhoneNumber>(verificationCode);

            return Ok(response);
        }

        [HttpPost(ApiRoutes.AccountRoutes.VerifyPhoneNumberAsync)]
        public async Task<IActionResult> VerifyPhoneNumberAsync([FromBody] AddPhoneNumber phoneNumber)
        {
            string responseMsg;
            ApplicationUser user;
            try
            {
                user = await _userManager.FindByIdAsync(phoneNumber.Id);
                if (user == null)
                {
                    _logger.LogError("~/Account/VerifyPhoneNumber(VerifyPhoneNumberViewModel) - userManager unable to retrieve User Id:{0}'s information. This should have been a valid user.", phoneNumber.Id);
                    return Unauthorized();
                }
            }
            catch(Exception ex)
            {
                _logger.LogError("UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503,"Error connecting to the database.");
            }

            IdentityResult result;
            try
            {
                result = await _userManager.ChangePhoneNumberAsync(user, phoneNumber.PhoneNumber, phoneNumber.Code);
                if (!result.Succeeded)
                {
                    _logger.LogError("~/Account/VerifyPhoneNumber(VerifyPhoneNumber) - userManager unable to add/change phone number for {0}'s account.", user.Id);
                    responseMsg = "An error occurred while attempting to verifiy your phone number. Did you enter the correct Verification Code?";
                    return StatusCode(400,responseMsg);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered an error. Connecting to the database? {0}", ex);
                return StatusCode(503, "Error connecting to the database.");
            }

            responseMsg = "The phone number verification was a success";
            _logger.LogInformation("User id:{0} successfully verified thier phone number.", phoneNumber.Id);

            return Ok(responseMsg);
        }

        [HttpPost(ApiRoutes.AccountRoutes.RemovePhoneNumberAsync)]
        public async Task<IActionResult> RemovePhoneNumberAsync([FromQuery] string id)
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
                return StatusCode(503, "Error connecting to the database.");
            }


            IdentityResult result;
            try
            {
               result = await _userManager.SetPhoneNumberAsync(user, null);
                if (!result.Succeeded)
                {
                    _logger.LogError("~/Account/RemovePhoneNumberAsync - and error occured removing a phone number from id:{0}'s account information.", id);
                    return StatusCode(500, "Error occurred removing User's phone number.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, "Error connecting to the database.");
            }

            return Ok();
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
                return StatusCode(503, "Error connecting to the database.");
            }

            IdentityResult result;
            try
            {
                result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (!result.Succeeded)
                {
                    _logger.LogError("~/Account/ChangePasswordAsync(ChanagePassword) - userManager unable to change password for id:{0}'s account.", model.Id);
                    return StatusCode(500,$"An error occurred changing the password for account.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("UserManger encountered and error connecting to the database. {0}", ex);
                return StatusCode(503, "Error connecting to the database.");
            }

            return Ok();
        }
        #endregion













        #region - Helper Methods
        private string EncodeUrlWebString(string stringToEncode)
        {
            byte[] stringToBytes = Encoding.UTF8.GetBytes(stringToEncode);
            string encodedUrlWebString = WebEncoders.Base64UrlEncode(stringToBytes);
            return encodedUrlWebString;
        }

        private string DecodeUrlWebString(string stringToDecode)
        {
            byte[] decodeStringToBytes = WebEncoders.Base64UrlDecode(stringToDecode);
            string decodedString = Encoding.UTF8.GetString(decodeStringToBytes);
            return decodedString;
        }
        #endregion
    }
}

