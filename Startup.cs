using System;
using System.Configuration;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(oidc_winform.Startup))]

namespace oidc_winform
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var oktaAudience = "api://winform";
            var oktaAuthority = "https://twu.oktapreview.com/oauth2/default";

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
               oktaAuthority + "/.well-known/openid-configuration",
               new OpenIdConnectConfigurationRetriever(),
               new HttpDocumentRetriever());
            var discoveryDocument = Task.Run(() => configurationManager.GetConfigurationAsync()).GetAwaiter().GetResult();
        }
    }
}
