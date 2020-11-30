using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;
using Serilog.Core;
using System;
using System.Net.Mail;
using System.Threading.Tasks;
using Twilio;
using Twilio.Exceptions;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace IdManagement.Services.MessageService
{
    public class AuthMessageSender : IEmailSender, ISmsSender
    {
        //Email
        private string _smtpServer;
        private int _smtpPort;
        private string _fromAddress;
        private string _fromAddressTitle;
        private string _username;
        private string _password;
        private bool _enableSsl;

        //SMS
        private string _SMSAccountId;
        private string _SMSAccountFrom;
        private string _SMSAuthToken;

        private ILogger<AuthMessageSender> _logger;
        public AuthMessageSender(IConfiguration configuration, ILogger<AuthMessageSender> logger)
        {
            _logger = logger;

            //Email
            _smtpServer = configuration["Email:SmtpServer"];
            _smtpPort = int.Parse(configuration["Email:SmtpPort"]);
            _smtpPort = _smtpPort == 0 ? 25 : _smtpPort;
            _fromAddress = configuration["Email:FromAddress"];
            _fromAddressTitle = configuration["FromAddressTitle"];
            _username = configuration["Email:SmtpUsername"];
            _password = configuration["Email:SmtpPassword"];
            _enableSsl = bool.Parse(configuration["Email:EnableSsl"]);

            //SMS
            _SMSAccountId = configuration["SMS:AccountSId"]; 
            _SMSAccountFrom = configuration["SMS:AccountFrom"];
            _SMSAuthToken = configuration["SMS:AuthToken"];
        }


        public async Task<int> SendEmailAsync(string email, string subject, string message)
        {
            // MIME : Multipurpose Internet Mail Extension
            var mimeMessage = new MimeMessage(); 
            mimeMessage.From.Add(new MailboxAddress(_fromAddressTitle, _fromAddress));
            mimeMessage.To.Add(new MailboxAddress(email));
            mimeMessage.Subject = subject;

            var bodyBuilder = new MimeKit.BodyBuilder
            {
                HtmlBody = message
            };
            mimeMessage.Body = bodyBuilder.ToMessageBody();

            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    client.Connect(_smtpServer, _smtpPort, _enableSsl);
                    //If using GMail this requires turning on LessSecureApps : https://myaccount.google.com/lesssecureapps
                    client.Authenticate(_username, _password);
                    await client.SendAsync(mimeMessage);
                    _logger.LogInformation("A email was sent to {0}. Message sent: {1}", email, mimeMessage.Body);
                }
                catch (SmtpException ex)
                {
                    _logger.LogError("An error occurred sending a confimation email: {0}, Message:{1}", ex, ex.Message);
                    throw;
                }
                finally
                {
                    client.Disconnect(true);
                }              
            }
            return await Task.FromResult(0);
        }

        public async Task<int> SendEmailConfirmationAsync(string email, string callbackUrl)
        {
            var mimeMessage = new MimeMessage(); 
            mimeMessage.From.Add(new MailboxAddress(_fromAddressTitle, _fromAddress));
            mimeMessage.To.Add(new MailboxAddress(email));
            mimeMessage.Subject = "Confirm new account";

            var bodyBuilder = new MimeKit.BodyBuilder
            {
                HtmlBody = $"<p>If this email comes to your junk folder, copy and paste the link into your browser's address bar, OR click the 'Not Junk' link to move this email to your inbox. At which point, the link will become clickable and it will tell your email client that further emails from Systems Design is safe to put into the inbox.</p><br /><br /> {callbackUrl}"
            };
            mimeMessage.Body = bodyBuilder.ToMessageBody();

            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    client.Connect(_smtpServer, _smtpPort, _enableSsl);

                    client.Authenticate(_username, _password);

                    await client.SendAsync(mimeMessage);
                    _logger.LogInformation("A confirmation email was sent to {0}. Message sent: {1}", email, mimeMessage.Body);
                }
                catch (SmtpException ex)
                {
                    _logger.LogError("An error occurred sending a confimation email: {0}, Message:{1}", ex, ex.Message);
                    throw;
                }
                finally
                {
                    client.Disconnect(true);
                }
            }
            return await Task.FromResult(0);
        }

        public Task SendSmsAsync(string number, string message)
        {
            try
            {
                TwilioClient.Init(_SMSAccountId, _SMSAuthToken);

                _logger.LogInformation("An Sms Message was sent to {0}, Message:{1}", number, message);

                return MessageResource.CreateAsync(
                  to: new PhoneNumber(number),
                  from: new PhoneNumber(_SMSAccountFrom),
                  body: message);
            }
            catch (TwilioException ex)
            {
                _logger.LogError("An error occurred sending a text message Exception: {0}, Message: {1}", ex, ex.Message);
                throw;
            }
        }
    }
}
