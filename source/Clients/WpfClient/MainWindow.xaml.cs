using Newtonsoft.Json.Linq;

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;
using System.Windows;

using SampleWCFApiHost;
using SampleWCFApiHost.CustomToken;

using Thinktecture.IdentityModel.Client;
using Thinktecture.Samples;

using Binding = System.Windows.Data.Binding;
using Constants = Sample.Constants;
using IChannel = System.Runtime.Remoting.Channels.IChannel;

namespace WpfClient
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        LoginWebView _login;
        AuthorizeResponse _response;

        public MainWindow()
        {
            InitializeComponent();

            _login = new LoginWebView();
            _login.Done += _login_Done;

            Loaded += MainWindow_Loaded;
        }

        void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _login.Owner = this;
        }

        void _login_Done(object sender, AuthorizeResponse e)
        {
            _response = e;
            Textbox1.Text = e.Raw;
        }

        private void LoginOnlyButton_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("openid", "id_token");
        }

        private void LoginWithProfileButton_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("openid profile", "id_token");
        }

        private void LoginWithAllClaimsButton_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("openid all_claims", "id_token");
        }

        private void LoginWithProfileAndAccessTokenButton_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("openid profile read write", "id_token token");
        }

        private void LoginWithProfileRolesAndAccessTokenButton_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("openid profile roles read write", "id_token token");
        }

        private void AccessTokenOnlyButton_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("read write", "token");
        }

        private void IdentityManager_Click(object sender, RoutedEventArgs e)
        {
            RequestToken("idmgr", "token");
        }

        private void RequestToken(string scope, string responseType)
        {
            var client = new OAuth2Client(new Uri(Constants.AuthorizeEndpoint));
            //var client = new OAuth2Client(new Uri("https://login.microsoftonline.com/70248591-7dbf-4c5c-a3e3-0a009f207bb2/oauth2/authorize"));
            var startUrl = client.CreateAuthorizeUrl(
                clientId: "implicitclient",
                //clientId: "7b3e70c3-32f7-4b32-82b9-93260ff47b47",
                responseType: responseType,
                scope: scope,
                redirectUri: "oob://localhost/wpfclient",
                state: "random_state",
                nonce: "random_nonce" /**,
                loginHint: "alice",
                acrValues: "idp:Google b c" **/);

            _login.Show();
            _login.Start(new Uri(startUrl), new Uri("oob://localhost/wpfclient"));
        }

        private async void CallUserInfo_Click(object sender, RoutedEventArgs e)
        {
            var client = new HttpClient
            {
                BaseAddress = new Uri(Constants.UserInfoEndpoint)
            };

            // authorization header
            if (_response != null && _response.Values.ContainsKey("access_token"))
            {
                client.SetBearerToken(_response.AccessToken);
            }

            var response = await client.GetAsync("");

            // form post
            //HttpResponseMessage response;
            //if (_response != null && _response.Values.ContainsKey("access_token"))
            //{
            //    var body = new Dictionary<string, string>
            //    {
            //        { "access_token", _response.AccessToken }
            //    };

            //    response = await client.PostAsync("", new FormUrlEncodedContent(body));
            //}
            //else
            //{
            //    return;
            //}

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var json = await response.Content.ReadAsStringAsync();
                Textbox1.Text = JObject.Parse(json).ToString();
            }
            else
            {
                MessageBox.Show(response.StatusCode.ToString());
            }
        }

        private void ShowIdTokenButton_Click(object sender, RoutedEventArgs e)
        {
            if (_response.Values.ContainsKey("id_token"))
            {
                var viewer = new IdentityTokenViewer();
                viewer.IdToken = _response.Values["id_token"];
                viewer.Show();
            }
        }

        private void ShowAccessTokenButton_Click(object sender, RoutedEventArgs e)
        {
            if (_response.Values.ContainsKey("access_token"))
            {
                var viewer = new IdentityTokenViewer();
                viewer.IdToken = _response.Values["access_token"];
                viewer.Show();
            }
        }

        private async void CallServiceButton_Click(object sender, RoutedEventArgs e)
        {
            var client = new HttpClient
            {
                BaseAddress = new Uri("http://localhost:2727/")
            };

            if (_response != null && _response.Values.ContainsKey("access_token"))
            {
                client.SetBearerToken(_response.AccessToken);
            }

            var response = await client.GetAsync("identity");

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var json = await response.Content.ReadAsStringAsync();
                Textbox1.Text = JArray.Parse(json).ToString();
            }
            else
            {
                MessageBox.Show(response.StatusCode.ToString());
            }
        }

        private async void ValidateIdTokenButton_Click(object sender, RoutedEventArgs e)
        {
            if (_response != null && _response.Values.ContainsKey("id_token"))
            {
                var client = new HttpClient();

                var response = await client.GetAsync(Constants.IdentityTokenValidationEndpoint + "?token=" + _response.Values["id_token"] + "&client_id=implicitclient");

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    Textbox1.Text = JObject.Parse(json).ToString();
                }
                else
                {
                    MessageBox.Show(response.StatusCode.ToString());
                }
            }
        }

        private void CallWcfServiceButton_Click(object sender, RoutedEventArgs e)
        {
            var token = "";
            if (_response != null && _response.Values.ContainsKey("access_token"))
            {
                //client.SetBearerToken(_response.AccessToken);
                token = _response.AccessToken;
            }


            CustomBinding customTokenBinding = CreateCustomTokenBinding();

            customTokenBinding.ReceiveTimeout = new TimeSpan(12, 0, 0);
            customTokenBinding.SendTimeout = new TimeSpan(12, 0, 0);
            customTokenBinding.OpenTimeout = new TimeSpan(12, 0, 0);
            customTokenBinding.CloseTimeout = new TimeSpan(12, 0, 0);

            var endPointIdentity = new DnsEndpointIdentity("idsrv3test");

            var serviceAddress = new EndpointAddress(new Uri("http://localhost:2729/Service1.svc"), endPointIdentity);

            // Create a client with given client endpoint configuration
            var channelFactory = new ChannelFactory<IService1>(customTokenBinding, serviceAddress);

            // configure the credit card credentials on the channel factory 
            CustomTokenClientCredentials credentials = new CustomTokenClientCredentials(token);

            // configure the service certificate on the credentials
            credentials.ServiceCertificate.DefaultCertificate = LoadCertificate();

            // replace ClientCredentials with CreditCardClientCredentials
            channelFactory.Endpoint.Behaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.Behaviors.Add(credentials);

            var client = channelFactory.CreateChannel();

            var response = client.GetIdentityData();

            ((ICommunicationObject)client).Close();
            channelFactory.Close();


            Textbox1.Text = response;
        }

        public CustomBinding CreateCustomTokenBinding()
        {
            HttpTransportBindingElement httpTransport = new HttpTransportBindingElement();

            // the message security binding element will be configured to require a credit card
            // token that is encrypted with the service's certificate 
            SymmetricSecurityBindingElement messageSecurity = new SymmetricSecurityBindingElement();
            messageSecurity.EndpointSupportingTokenParameters.SignedEncrypted.Add(new CustomTokenParameters());

            X509SecurityTokenParameters x509ProtectionParameters = new X509SecurityTokenParameters();
            x509ProtectionParameters.InclusionMode = SecurityTokenInclusionMode.Never;
            messageSecurity.ProtectionTokenParameters = x509ProtectionParameters;

            return new CustomBinding(messageSecurity, httpTransport);
        }

        static X509Certificate2 LoadCertificate()
        {
            return new X509Certificate2(
                string.Format(@"{0}\config\idsrv3test.pfx", AppDomain.CurrentDomain.BaseDirectory), "idsrv3test");
        }
    }
}