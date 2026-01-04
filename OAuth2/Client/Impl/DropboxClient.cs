using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;

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
                Resource = "/2/users/get_current_account"
            };
        }
        
        protected override UserInfo ParseUserInfo(string content)
        {
            throw new System.NotImplementedException();
        }
    }
}