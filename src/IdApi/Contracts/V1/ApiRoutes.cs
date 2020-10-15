namespace IdApi.Contracts.V1
{
    internal static class ApiRoutes
    {
        internal const string Root = "api";
        internal const string Version = "v1";
        internal const string Base = Root + "/" + Version;

        internal static class AccountRoutes
        {
            internal const string GetUserAccountAsync = Base + "/Account/{id}";
            internal const string RegisterAccountAsync = Base + "/Account/RegisterAccountAsync";
            internal const string ValidUserNameAsync = Base + "/Account/ValidUserNameAsync";
            internal const string VaildUserEmailAsync = Base + "/Account/ValidUserEmailAsync";
            internal const string ConfirmEmailAsync = Base + "/Account/ConfirmEmailAsync";

            internal const string AddPhoneNumberAsync = Base + "/Account/AddPhoneNumberAsync";
            internal const string VerifyPhoneNumberAsync = Base + "/Account/VerifyPhoneNumberAsync";
            internal const string RemovePhoneNumberAsync = Base + "/Account/RemovePhoneNumberAsync";

            internal const string ChangePasswordAsync = Base + "/Account/ChangePasswordAsync";

            internal const string ForgotPasswordAsync = Base + "/Account/ForgotPasswordAsync";
            internal const string ResetPasswordAsync = Base + "/Account/ResetPasswordAsync";

            internal const string Disable2faAsync = Base + "/Account/Disable2faAsync";
            internal const string EnableAuthenticatorAsync = Base + "/Account/EnableAuthenticatorAsync";
            internal const string LoadSharedKeyAndQrCodeUriAsync = Base + "/Account/LoadSharedKeyAndQrCodeUriAsync";
        }
    }
}
