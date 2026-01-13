using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp;
using RestSharp.Authenticators;
using System;
using System.Security.Cryptography;
using System.Text;


namespace OAuth2.Client.Impl
{
    public static class PkceHelper
    {
        /// <summary>
        /// Generates a PKCE code_verifier and code_challenge pair from a provided Guid.
        /// </summary>
        public static (string CodeVerifier, string CodeChallenge) GeneratePkcePair(Guid guid)
        {
            string codeVerifier = GenerateCodeVerifier(guid);
            string codeChallenge = GenerateCodeChallenge(codeVerifier);
            return (codeVerifier, codeChallenge);
        }

        /// <summary>
        /// Creates a PKCE-compliant verifier from a Guid.
        /// A single GUID (32 chars) is too short, so we concatenate two copies.
        /// </summary>
        private static string GenerateCodeVerifier(Guid guid)
        {
            // Guid in "N" format = 32 chars, so doubling gives 64 chars (valid PKCE length)
            string baseString = guid.ToString("N");
            return baseString + baseString;
        }

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                return Base64UrlEncode(hash);
            }
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
    }

    
    /// <summary>
    /// Windows Live authentication client.
    /// </summary>
    public class MicrosoftGraphClient : OAuth2Client
    {
        private string _codeVerifier;
        private string _codeChallenge;
        
        /// <summary>
        /// Initializes a new instance of the <see cref="MicrosoftGraphClient"/> class.
        /// </summary>
        /// <param name="factory">The factory.</param>
        /// <param name="configuration">The configuration.</param>
        public MicrosoftGraphClient(
            Guid stateId,
            IRequestFactory factory, IClientConfiguration configuration)
            : base(stateId, factory, configuration)
        {
            (_codeVerifier, _codeChallenge) = PkceHelper.GeneratePkcePair(_stateId);
        }

        /// <summary>
        /// Defines URI of service which issues access code.
        /// </summary>
        protected override Endpoint AccessCodeServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://login.microsoftonline.com",
                    Resource = "/consumers/oauth2/v2.0/authorize"
                };
            }
        }

        /// <summary>
        /// Defines URI of service which issues access token.
        /// </summary>
        protected override Endpoint AccessTokenServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://login.microsoftonline.com",
                    Resource = "/consumers/oauth2/v2.0/token"
                };
            }
        }

        /// <summary>
        /// Defines URI of service which allows to obtain information about user which is currently logged in.
        /// </summary>
        protected override Endpoint UserInfoServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://graph.microsoft.com/v1.0",
                    Resource = "/me"
                };
            }
        }

        /// <summary>
        /// Called just before issuing request to third-party service when everything is ready.
        /// Allows to add extra parameters to request or do any other needed preparations.
        /// </summary>
        protected override void BeforeGetUserInfo(BeforeAfterRequestArgs args)
        {
            args.Client.Authenticator = new OAuth2AuthorizationRequestHeaderAuthenticator(
                AccessToken, "Bearer");
        }


        protected override void BeforeGetAccessToken(BeforeAfterRequestArgs args)
        {
            base.BeforeGetAccessToken(args);
            if (args.Parameters.Get("code") != null)
            {
                args.Request.AddHeader("scope", "User.Read");
                args.Request.AddObject(new { code_verifier = _codeVerifier });            }
            else
            {
                args.Request.AddHeader("scope", "User.Read");
            }
        }
        

        /// <summary>
        /// Should return parsed <see cref="UserInfo"/> from content received from third-party service.
        /// </summary>
        /// <param name="content">The content which is received from third-party service.</param>
        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            const string avatarUriTemplate = @"https://cid-{0}.users.storage.live.com/users/0x{0}/myprofile/expressionprofile/profilephoto:Win8Static,{1},UserTileStatic/MeControlXXLUserTile?ck=2&ex=24";
            var userinfo =  new UserInfo
            {
                Id = response["id"].Value<string>(),
                FirstName = response["givenName"].Value<string>(),
                LastName = response["surname"].Value<string>(),
                /*AvatarUri =
                    {
                        Small = string.Format(avatarUriTemplate, response["id"].Value<string>(), "UserTileSmall"),
                        Normal = string.Format(avatarUriTemplate, response["id"].Value<string>(), "UserTileSmall"),
                        Large = string.Format(avatarUriTemplate, response["id"].Value<string>(), "UserTileLarge")
                    }*/
            };

            if (Configuration.Scope != null && Configuration.Scope.ToUpperInvariant().Contains("WL.EMAILS"))
            {
                userinfo.Email = response["emails"]["preferred"].SafeGet(x => x.Value<string>());
            }

            return userinfo;
        }

        
        protected override void FineTuneLoginRequest(IRestRequest request)
        {
            base.FineTuneLoginRequest(request);
            
            request.AddObject(new
            {
                code_challenge = _codeChallenge,
                code_challenge_method = "S256"
            });
        }
        

        public override string Name
        {
            get { return "MicrosoftGraph"; }
        }
    }
}
