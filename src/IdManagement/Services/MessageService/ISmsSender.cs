using System.Threading.Tasks;

namespace IdManagement.Services.MessageService
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
