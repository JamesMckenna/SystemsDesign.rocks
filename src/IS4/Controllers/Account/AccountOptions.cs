// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;

namespace IS4.Controllers
{
    public class AccountOptions
    {
        public static bool AllowLocalLogin = true;
        public static bool AllowRememberLogin = true;
        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(1);

        public static bool ShowLogoutPrompt = true;//Was false I changed to true
        public static bool AutomaticRedirectAfterSignOut = false;//Was true, I set to false

        public static string InvalidCredentialsErrorMessage = "Invalid Username, Email or Password";
    }
}
