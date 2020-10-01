using Microsoft.Extensions.Configuration;
using MimeKit;
using System.Threading.Tasks;
using Twilio;
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

        public AuthMessageSender(IConfiguration configuration)
        {
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
                client.Connect(_smtpServer, _smtpPort, _enableSsl);

                //If using GMail this requires turning on LessSecureApps : https://myaccount.google.com/lesssecureapps
                client.Authenticate(_username, _password);

                await client.SendAsync(mimeMessage);

                client.Disconnect(true);
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
                HtmlBody = callbackUrl
            };
            mimeMessage.Body = bodyBuilder.ToMessageBody();

            using (var client = new MailKit.Net.Smtp.SmtpClient())
            {
                client.Connect(_smtpServer, _smtpPort, _enableSsl);

                client.Authenticate(_username, _password); 

                await client.SendAsync(mimeMessage);

                client.Disconnect(true);
            }
            return await Task.FromResult(0);
        }

        public Task SendSmsAsync(string number, string message)
        {
            TwilioClient.Init(_SMSAccountId, _SMSAuthToken);

            return MessageResource.CreateAsync(
              to: new PhoneNumber(number),
              from: new PhoneNumber(_SMSAccountFrom),
              body: message);
        }
    }
}
