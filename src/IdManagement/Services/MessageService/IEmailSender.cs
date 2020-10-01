using System.Threading.Tasks;

namespace IdManagement.Services.MessageService
{
    public interface IEmailSender
    {
        Task<int> SendEmailAsync(string email, string subject, string message);
        Task<int> SendEmailConfirmationAsync(string email, string callbackUrl);
    }
}
