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
        public DropboxClient(IRequestFactory factory, IClientConfiguration configuration) : base(factory, configuration)
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
                BaseUri = "https://www.dropbox.com",
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
                Resource = "/2/users/get_current_account",
                
            };
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

        protected override IRestRequest CreateUserInfoRequest(Endpoint endpoint)
        {
            return _factory.CreateRequest(UserInfoServiceEndpoint, Method.POST);
        }

        
        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            const string avatarUriTemplate = @"https://cid-{0}.users.storage.live.com/users/0x{0}/myprofile/expressionprofile/profilephoto:Win8Static,{1},UserTileStatic/MeControlXXLUserTile?ck=2&ex=24";
            var userinfo =  new UserInfo
            {
                Id = response["account_id"].Value<string>(),
                FirstName = response["name"]["given_name"].Value<string>(),
                LastName = response["name"]["surname"].Value<string>(),
                /*AvatarUri =
                    {
                        Small = string.Format(avatarUriTemplate, response["id"].Value<string>(), "UserTileSmall"),
                        Normal = string.Format(avatarUriTemplate, response["id"].Value<string>(), "UserTileSmall"),
                        Large = string.Format(avatarUriTemplate, response["id"].Value<string>(), "UserTileLarge")
                    }*/
            };

            
            if (response.ContainsKey("email")) {
                userinfo.Email = response["email"].Value<string>();
            }

            return userinfo;
        }

    }
}