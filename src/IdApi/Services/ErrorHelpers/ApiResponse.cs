namespace IdApi.Services.ErrorHelpers
{
    public class ApiResponse
    {
        public int StatusCode { get; }

        public string Message { get; }
        
        public ApiResponse(int statusCode, string message = null)
        {
            StatusCode = statusCode;
            Message = message ?? GetDefaultMessageForStatusCode(statusCode);
        }

        //The 'Friendly' part of the returned error message
        private static string GetDefaultMessageForStatusCode(int statusCode)
        {
            return statusCode switch
            {
                400 => "Bad Request: Our helper Elves are telling us that a bad request was made.",
                401 => "Unauthorized: Our helper Elves counld not find a vaild access token.",
                403 => "Forbidden: Our help Elves are not able to proceed with your request.",
                404 => "Resource Not Found: Our helper Elves could find what you are looking for.",
                408 => "Request Timeout: Our helper Elves must be on a coffee break.", 
                500 => "Internal Error: Our helper Elves are looking into it.",
                501 => "Not Implemented: Our helper Elves weren't able to preform that action for you.",
                _ => null,
            };
        }
    }
}
