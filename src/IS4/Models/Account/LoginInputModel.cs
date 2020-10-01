// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.ComponentModel.DataAnnotations;

namespace IS4.Models
{
    public class LoginInputModel
    {
        [Required]
        [Display(Name = "Email Address or Username")]//IS4 QUiCKSTART was just Username, I extended Account Controller Login Action to accept either Username or Email
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }
}