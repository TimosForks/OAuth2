using System;
using RestSharp;

namespace OAuth2.Client
{
    /// <summary>
    /// Indicates unexpected response from service.
    /// </summary>
    public class UnexpectedResponseException : Exception
    {
        /// <summary>
        /// Name of field which contains unexpected (GET) response.
        /// </summary>
        public string FieldName { get; set; }

        /// <summary>
        /// Unexpected response itself (can be null, if error occured later in the response processing pipeline).
        /// </summary>
        public IRestResponse Response { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="UnexpectedResponseException"/> class.
        /// </summary>
        /// <param name="response">The response.</param>
        public UnexpectedResponseException(IRestResponse response)
            : base(BuildMessage(response))
        {
            Response = response;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UnexpectedResponseException"/> class.
        /// </summary>
        /// <param name="fieldName">Name of the field.</param>
        public UnexpectedResponseException(string fieldName)
            : base($"Unexpected response: missing or invalid field '{fieldName}'")
        {
            FieldName = fieldName;
        }

        private static string BuildMessage(IRestResponse response)
        {
            if (response == null)
                return "Unexpected response: response is null";

            var content = response.Content;
            if (string.IsNullOrEmpty(content))
                content = "(empty response)";
            else if (content.Length > 500)
                content = content.Substring(0, 500) + "...";

            return $"Unexpected response: StatusCode={response.StatusCode}, Content={content}";
        }
    }
}