using IdentityModel;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;

namespace oidc_winform
{
    public partial class Form1 : Form
    {

        private static async Task<string[]> GetAuthzCode(string u, string p)
        {
            var domain = @"https://[your org].oktapreview.com";//or okta.com
            var oktaAuthorizationServer = "[authz server id]";//security|api
            var clientId = "[client id]";//from appication|name|general
            var redirectUrl = @"http://localhost:8080/callback";//this much
            var redirectUrlEncoded = System.Net.WebUtility.UrlEncode(redirectUrl);
            var responseType = "code";
            var state = "a_state";
            var nonce = "a_nonce";
            var scope = System.Net.WebUtility.UrlEncode("openid email profile");
            var authnUri = @"https://twu.oktapreview.com/api/v1/authn";
            var username = u;
            var password = p;

            dynamic bodyOfRequest = new
            {
                username,
                password,
                options = new
                {
                    multiOptionalFactorEnroll = false,
                    warnBeforePasswordExpired = false,
                },
            };

            var body = JsonConvert.SerializeObject(bodyOfRequest);

            var stringContent = new StringContent(body, Encoding.UTF8, "application/json");

            string sessionToken;

            HttpClientHandler httpClientHandler = new HttpClientHandler();
            httpClientHandler.AllowAutoRedirect = false;

            using (var httpClient = new HttpClient(httpClientHandler))
            {
                httpClient.DefaultRequestHeaders
                    .Accept
                    .Add(new MediaTypeWithQualityHeaderValue("application/json"));

                HttpResponseMessage authnResponse = await httpClient.PostAsync(authnUri, stringContent);

                if (authnResponse.IsSuccessStatusCode)
                {
                    var authnResponseContent = await authnResponse.Content.ReadAsStringAsync();
                    dynamic authnObject = JsonConvert.DeserializeObject(authnResponseContent);
                    sessionToken = authnObject.sessionToken;

                    var codeVerifier = CryptoRandom.CreateUniqueId(32); 
                    string codeChallenge;
                    using (var sha256 = SHA256.Create())
                    {
                        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                        codeChallenge = Base64Url.Encode(challengeBytes);
                    }

                    var authorizeUri = $"{domain}/oauth2/{oktaAuthorizationServer}/v1/authorize?client_id={clientId}" +
                        $"&redirect_uri={redirectUrlEncoded}&response_type={responseType}&sessionToken={sessionToken}" +
                        $"&state={state}&nonce={nonce}&scope={scope}&code_challenge={codeChallenge}&code_challenge_method=S256";


                    HttpResponseMessage authorizeResponse = await httpClient.GetAsync(authorizeUri);
                    var statusCode = (int)authorizeResponse.StatusCode;

                    if (statusCode == (int)HttpStatusCode.Found)
                    {
                        var redirectUri = authorizeResponse.Headers.Location;
                        var queryDictionary = HttpUtility.ParseQueryString(redirectUri.AbsoluteUri);
                        string[] rtnArray = new string[2];
                        rtnArray[0] = queryDictionary[0];
                        rtnArray[1] = codeVerifier;
                        return rtnArray;
                    }
                }
            }

            return null;
        }

        private void GetAccessToken(string authzCode, string codeVerifier, ref string a, ref string b)
        {
            var domain = @"https://[your org].oktapreview.com";//or okta.com
            var oktaAuthorizationServer = "[authz server id]";//security|api
            var clientId = "[client id]";//from appication|name|general
            var redirectUrl = @"http://localhost:8080/callback";//this much
            var redirect_uri = System.Net.WebUtility.UrlEncode(redirectUrl);
            var grant_type = "authorization_code";
            var code = authzCode;
            var code_verifier = codeVerifier;

            var addParam = $"grant_type=authorization_code&client_id={client_id}&code_verifier={code_verifier}&code={code}&redirect_uri={redirect_uri}";

            var tokenUri = $"{domain}/oauth2/{oktaAuthorizationServer}/v1/token";
            var client = new RestClient(tokenUri);
            var request = new RestRequest(Method.POST);
            request.AddHeader("content-type", "application/x-www-form-urlencoded");
            request.AddParameter("application/x-www-form-urlencoded", addParam, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            _ = response.Content;
            if (response.Content.Contains("access_token"))
            {
                var jObject = Newtonsoft.Json.Linq.JObject.Parse(response.Content);
                a = jObject.GetValue("access_token").ToString();
                b = jObject.GetValue("id_token").ToString();
            }
        }

        public Form1()
        {
            InitializeComponent();
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            var getArray = await GetAuthzCode(textBox1.Text, textBox2.Text);
            textBox3.Text = getArray[0];
            textBox4.Text = getArray[1];
        }

        private void button2_Click(object sender, EventArgs e)
        {
            string atoken = "";
            string itoken = "";
            GetAccessToken(textBox3.Text, textBox4.Text, ref atoken, ref itoken);
            textBox6.Text = atoken;
            textBox5.Text = itoken;
        }
    }
}
