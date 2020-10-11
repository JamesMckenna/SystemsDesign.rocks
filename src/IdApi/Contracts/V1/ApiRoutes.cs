namespace IdApi.Contracts.V1
{
    internal static class ApiRoutes
    {
        internal const string Root = "api";
        internal const string Version = "v1";
        internal const string Base = Root + "/" + Version;

        internal static class AccountRoutes
        {
            internal const string Index = Base + "/Account";
            internal const string GetUserAccountAsync = Base + "/Account/{id}";
            internal const string RegisterAccountAsync = Base + "/Account/RegisterAccountAsync";
            internal const string ValidUserNameAsync = Base + "/Account/ValidUserNameAsync";
            internal const string VaildUserEmailAsync = Base + "/Account/ValidUserEmailAsync";
            internal const string ConfirmEmailAsync = Base + "/Account/ConfirmEmailAsync";

            internal const string AddPhoneNumberAsync = Base + "/Account/AddPhoneNumberAsync";
            internal const string VerifyPhoneNumberAsync = Base + "/Account/VerifyPhoneNumberAsync";
            internal const string RemovePhoneNumberAsync = Base + "/Account/RemovePhoneNumberAsync";
        }
    }
}
