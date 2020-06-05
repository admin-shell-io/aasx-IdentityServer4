using Clients;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace ConsolePrivateKeyJwtClient
{
    public class Program
    {
        private static string rsaKey = "{'d':'GmiaucNIzdvsEzGjZjd43SDToy1pz-Ph-shsOUXXh-dsYNGftITGerp8bO1iryXh_zUEo8oDK3r1y4klTonQ6bLsWw4ogjLPmL3yiqsoSjJa1G2Ymh_RY_sFZLLXAcrmpbzdWIAkgkHSZTaliL6g57vA7gxvd8L4s82wgGer_JmURI0ECbaCg98JVS0Srtf9GeTRHoX4foLWKc1Vq6NHthzqRMLZe-aRBNU9IMvXNd7kCcIbHCM3GTD_8cFj135nBPP2HOgC_ZXI1txsEf-djqJj8W5vaM7ViKU28IDv1gZGH3CatoysYx6jv1XJVvb2PH8RbFKbJmeyUm3Wvo-rgQ','dp':'YNjVBTCIwZD65WCht5ve06vnBLP_Po1NtL_4lkholmPzJ5jbLYBU8f5foNp8DVJBdFQW7wcLmx85-NC5Pl1ZeyA-Ecbw4fDraa5Z4wUKlF0LT6VV79rfOF19y8kwf6MigyrDqMLcH_CRnRGg5NfDsijlZXffINGuxg6wWzhiqqE','dq':'LfMDQbvTFNngkZjKkN2CBh5_MBG6Yrmfy4kWA8IC2HQqID5FtreiY2MTAwoDcoINfh3S5CItpuq94tlB2t-VUv8wunhbngHiB5xUprwGAAnwJ3DL39D2m43i_3YP-UO1TgZQUAOh7Jrd4foatpatTvBtY3F1DrCrUKE5Kkn770M','e':'AQAB','kid':'ZzAjSnraU3bkWGnnAqLapYGpTyNfLbjbzgAPbbW2GEA','kty':'RSA','n':'wWwQFtSzeRjjerpEM5Rmqz_DsNaZ9S1Bw6UbZkDLowuuTCjBWUax0vBMMxdy6XjEEK4Oq9lKMvx9JzjmeJf1knoqSNrox3Ka0rnxXpNAz6sATvme8p9mTXyp0cX4lF4U2J54xa2_S9NF5QWvpXvBeC4GAJx7QaSw4zrUkrc6XyaAiFnLhQEwKJCwUw4NOqIuYvYp_IXhw-5Ti_icDlZS-282PcccnBeOcX7vc21pozibIdmZJKqXNsL1Ibx5Nkx1F1jLnekJAmdaACDjYRLL_6n3W4wUp19UvzB1lGtXcJKLLkqB6YDiZNu16OSiSprfmrRXvYmvD8m6Fnl5aetgKw','p':'7enorp9Pm9XSHaCvQyENcvdU99WCPbnp8vc0KnY_0g9UdX4ZDH07JwKu6DQEwfmUA1qspC-e_KFWTl3x0-I2eJRnHjLOoLrTjrVSBRhBMGEH5PvtZTTThnIY2LReH-6EhceGvcsJ_MhNDUEZLykiH1OnKhmRuvSdhi8oiETqtPE','q':'0CBLGi_kRPLqI8yfVkpBbA9zkCAshgrWWn9hsq6a7Zl2LcLaLBRUxH0q1jWnXgeJh9o5v8sYGXwhbrmuypw7kJ0uA3OgEzSsNvX5Ay3R9sNel-3Mqm8Me5OfWWvmTEBOci8RwHstdR-7b9ZT13jk-dsZI7OlV_uBja1ny9Nz9ts','qi':'pG6J4dcUDrDndMxa-ee1yG4KjZqqyCQcmPAfqklI2LmnpRIjcK78scclvpboI3JQyg6RCEKVMwAhVtQM6cBcIO3JrHgqeYDblp5wXHjto70HVW6Z8kBruNx1AH9E8LzNvSRL-JVTFzBkJuNgzKQfD0G77tQRgJ-Ri7qu3_9o1M4'}";
        
        public static async Task Main()
        {
            Console.Title = "Console Client Credentials Flow with JWT Assertion";

            // X.509 cert
            // var certificate = new X509Certificate2("client.p12", "changeit");
            var certificate = new X509Certificate2("Andreas_Orzelski_Chain.pfx", "i40");
            // var x509Credential = new X509SigningCredentials(certificate);
            X509SigningCredentials x509Credential = null;

            var response = await RequestTokenAsync(x509Credential);
            response.Show();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\nPress ENTER to access Aasx Server at " + baseAddress + "\n");
            Console.ResetColor();
            Console.ReadLine();
            await CallServiceAsync(response.AccessToken);

            /*
            // RSA JsonWebkey
            var jwk = new JsonWebKey(rsaKey);
            response = await RequestTokenAsync(new SigningCredentials(jwk, "RS256"));
            response.Show();
            
            Console.ReadLine();
            await CallServiceAsync(response.AccessToken);
            */
        }

        static async Task<TokenResponse> RequestTokenAsync(SigningCredentials credential)
        {
            var client = new HttpClient();

            var disco = await client.GetDiscoveryDocumentAsync(Constants.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var clientToken = CreateClientToken(credential,"client.jwt", disco.TokenEndpoint);
            // oz
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\nClientToken with x5c in header: \n");
            Console.ResetColor();
            Console.WriteLine(clientToken + "\n");

            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,
                // Scope = "feature1",
                Scope = "scope1",

                ClientAssertion =
                {
                    Type = OidcConstants.ClientAssertionTypes.JwtBearer,
                    Value = clientToken
                }
            });

            if (response.IsError) throw new Exception(response.Error);
            return response;
        }

        static string baseAddress = "http://localhost:51310";

        static async Task CallServiceAsync(string token)
        {
            // var baseAddress = Constants.SampleApi;

            var client = new HttpClient
            {
                BaseAddress = new Uri(baseAddress)
            };

            client.SetBearerToken(token);
            // var response = await client.GetStringAsync("identity");
            var response = await client.GetStringAsync("/server/listaas");

            "\n\nService claims:".ConsoleGreen();
            // Console.WriteLine(JArray.Parse(response));
            Console.WriteLine(response);
        }

        private static string CreateClientToken(SigningCredentials credential, string clientId, string audience)
        {
            // oz
            string x5c = "";
            string certFileName = "Andreas_Orzelski_Chain.pfx";
            string password = "i40";

            X509Certificate2Collection xc = new X509Certificate2Collection();
            xc.Import(certFileName, password, X509KeyStorageFlags.PersistKeySet);

            string[] X509Base64 = new string[xc.Count];

            int j = xc.Count;
            var xce = xc.GetEnumerator();
            for (int i = 0; i < xc.Count; i++)
            {
                xce.MoveNext();
                X509Base64[--j] = Convert.ToBase64String(xce.Current.GetRawCertData());
            }

            x5c = JsonConvert.SerializeObject(X509Base64);

            // Byte[] certFileBytes = Convert.FromBase64String(X509Base64[0]);
            // credential = new X509SigningCredentials(new X509Certificate2(certFileBytes));
            credential = new X509SigningCredentials(new X509Certificate2(certFileName, password));
            // oz end

            var now = DateTime.UtcNow;

            var token = new JwtSecurityToken(
                    clientId,
                    audience,
                    new List<Claim>()
                    {
                        new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString()),
                        new Claim(JwtClaimTypes.Subject, clientId),
                        new Claim(JwtClaimTypes.IssuedAt, now.ToEpochTime().ToString(), ClaimValueTypes.Integer64),
                        // OZ
                        new Claim(JwtClaimTypes.Email, "aorzelski@phoenixcontact.com")
                        // new Claim("x5c", x5c)
                    },
                    now,
                    now.AddMinutes(1),
                    credential)
            ;

            token.Header.Add("x5c", x5c);
            // oz

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }
    }
}