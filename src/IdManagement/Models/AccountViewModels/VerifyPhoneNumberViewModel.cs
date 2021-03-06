﻿using System.ComponentModel.DataAnnotations;

namespace IdManagement.Models.AccountViewModels
{
    public class VerifyPhoneNumberViewModel
    {
        [Required]
        public string Code { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Phone number")]
        public string PhoneNumber { get; set; }

        public string Id { get; set; }
    }
}
