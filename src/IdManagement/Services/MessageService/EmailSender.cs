using IdManagement.Services.MessageService;
using System.Threading.Tasks;

namespace IdManagement.Services
{
    public class EmailSender : IEmailSender
    {
        public Task<int> SendEmailAsync(string email, string subject, string message)
        {
            return Task.FromResult(0);
        }

        Task<int> IEmailSender.SendEmailConfirmationAsync(string email, string callbackUrl)
        {
            return Task.FromResult(0);
        }
    }
}
