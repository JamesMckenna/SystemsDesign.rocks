using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdManagement.Services.MessageService
{
    public class SMSSender : ISmsSender
    {
        public string SMSAccountId { get; set; }
        public string SMSAccountPW { get; set; }
        public string SMSAccountFrom { get; set; }
        Task ISmsSender.SendSmsAsync(string number, string message)
        {
            return Task.FromResult(0);
        }
    }
}
