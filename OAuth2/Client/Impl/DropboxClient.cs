using System;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp;
using RestSharp.Authenticators;

namespace OAuth2.Client.Impl
{
    public class DropboxClient : OAuth2Client
    {
        public DropboxClient(Guid stateId, IRequestFactory factory, IClientConfiguration configuration) : base(stateId, factory, configuration)
        {
        }

        public override string Name { get => "Dropbox"; }

        protected override Endpoint AccessCodeServiceEndpoint
        {
            get => new Endpoint()
            {
                BaseUri = "https://www.dropbox.com",
                Resource = "/oauth2/authorize"
            };
        }

        protected override Endpoint AccessTokenServiceEndpoint
        {
            get => new Endpoint()
            {
                BaseUri = "https://api.dropboxapi.com",
                Resource = "/oauth2/token"
            };
        }
        
        /**
         * https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account
         */
        protected override Endpoint UserInfoServiceEndpoint
        {
            get => new Endpoint()
            {
                BaseUri = "https://api.dropboxapi.com",
                Resource = "/2/users/get_current_account"
            };
        }
 
        protected override IRestRequest CreateUserInfoRequest(Endpoint endpoint)
        {
            return _factory.CreateRequest(UserInfoServiceEndpoint, Method.POST);
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
        
        protected override void FineTuneLoginRequest(IRestRequest request)
        {
            base.FineTuneLoginRequest(request);
            if (Configuration.IsOfflineToken)
            {
                request.AddObject(new
                {
                    token_access_type="offline"
                });
            }
        }
        
        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            var userinfo =  new UserInfo
            {
                Id = response["account_id"].SafeGet(x => x.Value<string>()),
                FirstName = response["name"]["given_name"].SafeGet(x => x.Value<string>()),
                LastName = response["name"]["surname"].SafeGet(x => x.Value<string>()),
                AvatarUri =
                {
                    Small = response["profile_photo_url"].SafeGet(x => x.Value<string>()),
                    Normal = response["profile_photo_url"].SafeGet(x => x.Value<string>()),
                    Large = response["profile_photo_url"].SafeGet(x => x.Value<string>())
                }
            };

            userinfo.Email = response["email"].SafeGet(x => x.Value<string>());

            return userinfo;
        }
    }
}