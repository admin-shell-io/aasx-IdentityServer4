// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using SSIExtension;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace IdentityServer4.Services
{
    /// <summary>
    /// Default token service
    /// </summary>
    public class DefaultTokenService : ITokenService
    {
        /// <summary>
        /// The logger
        /// </summary>
        protected readonly ILogger Logger;

        /// <summary>
        /// The HTTP context accessor
        /// </summary>
        protected readonly IHttpContextAccessor ContextAccessor;

        /// <summary>
        /// The claims provider
        /// </summary>
        protected readonly IClaimsService ClaimsProvider;

        /// <summary>
        /// The reference token store
        /// </summary>
        protected readonly IReferenceTokenStore ReferenceTokenStore;

        /// <summary>
        /// The signing service
        /// </summary>
        protected readonly ITokenCreationService CreationService;

        /// <summary>
        /// The clock
        /// </summary>
        protected readonly ISystemClock Clock;

        /// <summary>
        /// The key material service
        /// </summary>
        protected readonly IKeyMaterialService KeyMaterialService;

        /// <summary>
        /// The IdentityServer options
        /// </summary>
        protected readonly IdentityServerOptions Options;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultTokenService" /> class.
        /// </summary>
        /// <param name="claimsProvider">The claims provider.</param>
        /// <param name="referenceTokenStore">The reference token store.</param>
        /// <param name="creationService">The signing service.</param>
        /// <param name="contextAccessor">The HTTP context accessor.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="keyMaterialService"></param>
        /// <param name="options">The IdentityServer options</param>
        /// <param name="logger">The logger.</param>
        public DefaultTokenService(
            IClaimsService claimsProvider,
            IReferenceTokenStore referenceTokenStore,
            ITokenCreationService creationService,
            IHttpContextAccessor contextAccessor,
            ISystemClock clock,
            IKeyMaterialService keyMaterialService,
            IdentityServerOptions options,
            ILogger<DefaultTokenService> logger)
        {
            ContextAccessor = contextAccessor;
            ClaimsProvider = claimsProvider;
            ReferenceTokenStore = referenceTokenStore;
            CreationService = creationService;
            Clock = clock;
            KeyMaterialService = keyMaterialService;
            Options = options;
            Logger = logger;
        }

        /// <summary>
        /// Creates an identity token.
        /// </summary>
        /// <param name="request">The token creation request.</param>
        /// <returns>
        /// An identity token
        /// </returns>
        public virtual async Task<Token> CreateIdentityTokenAsync(TokenCreationRequest request)
        {
            Logger.LogTrace("Creating identity token");
            request.Validate();

            // todo: Dom, add a test for this. validate the at and c hashes are correct for the id_token when the client's alg doesn't match the server default.
            var credential = await KeyMaterialService.GetSigningCredentialsAsync(request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms);
            if (credential == null)
            {
                throw new InvalidOperationException("No signing credential is configured.");
            }

            var signingAlgorithm = credential.Algorithm;

            // host provided claims
            var claims = new List<Claim>();

            // if nonce was sent, must be mirrored in id token
            if (request.Nonce.IsPresent())
            {
                claims.Add(new Claim(JwtClaimTypes.Nonce, request.Nonce));
            }

            // add iat claim
            claims.Add(new Claim(JwtClaimTypes.IssuedAt, Clock.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

            // add at_hash claim
            if (request.AccessTokenToHash.IsPresent())
            {
                claims.Add(new Claim(JwtClaimTypes.AccessTokenHash, CryptoHelper.CreateHashClaimValue(request.AccessTokenToHash, signingAlgorithm)));
            }

            // add c_hash claim
            if (request.AuthorizationCodeToHash.IsPresent())
            {
                claims.Add(new Claim(JwtClaimTypes.AuthorizationCodeHash, CryptoHelper.CreateHashClaimValue(request.AuthorizationCodeToHash, signingAlgorithm)));
            }

            // add s_hash claim
            if (request.StateHash.IsPresent())
            {
                claims.Add(new Claim(JwtClaimTypes.StateHash, request.StateHash));
            }

            // add sid if present
            if (request.ValidatedRequest.SessionId.IsPresent())
            {
                claims.Add(new Claim(JwtClaimTypes.SessionId, request.ValidatedRequest.SessionId));
            }

            claims.AddRange(await ClaimsProvider.GetIdentityTokenClaimsAsync(
                request.Subject,
                request.ValidatedResources,
                request.IncludeAllIdentityClaims,
                request.ValidatedRequest));

            var issuer = ContextAccessor.HttpContext.GetIdentityServerIssuerUri();

            var token = new Token(OidcConstants.TokenTypes.IdentityToken)
            {
                CreationTime = Clock.UtcNow.UtcDateTime,
                Audiences = { request.ValidatedRequest.Client.ClientId },
                Issuer = issuer,
                Lifetime = request.ValidatedRequest.Client.IdentityTokenLifetime,
                Claims = claims.Distinct(new ClaimComparer()).ToList(),
                ClientId = request.ValidatedRequest.Client.ClientId,
                AccessTokenType = request.ValidatedRequest.AccessTokenType,
                AllowedSigningAlgorithms = request.ValidatedRequest.Client.AllowedIdentityTokenSigningAlgorithms
            };

            return token;
        }

        /// <summary>
        /// Creates an access token.
        /// </summary>
        /// <param name="request">The token creation request.</param>
        /// <returns>
        /// An access token
        /// </returns>
        public virtual async Task<Token> CreateAccessTokenAsync(TokenCreationRequest request)
        {
            Logger.LogTrace("Creating access token");
            request.Validate();

            var claims = new List<Claim>();
            claims.AddRange(await ClaimsProvider.GetAccessTokenClaimsAsync(
                request.Subject,
                request.ValidatedResources,
                request.ValidatedRequest));

            if (request.ValidatedRequest.Client.IncludeJwtId)
            {
                claims.Add(new Claim(JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex)));
            }

            if (request.ValidatedRequest.SessionId.IsPresent())
            {
                claims.Add(new Claim(JwtClaimTypes.SessionId, request.ValidatedRequest.SessionId));
            }

            // oz

            bool foundUserName = false;
            var jwtToken = new JwtSecurityToken((string) request.ValidatedRequest.Secret.Credential);
            Console.WriteLine("jwtToken: " + jwtToken);

            var entraid = "";
            var entraidClaim = jwtToken.Claims.Where(c => c.Type == "entraid");
            if (entraidClaim != null && entraidClaim.Any())
            {
                entraid = entraidClaim.First().Value;
                jwtToken = new JwtSecurityToken(entraid);
                Console.WriteLine("Replaced by entraid token: " + jwtToken);
            }

            var iss = "";
            var issClaim = jwtToken.Claims.Where(c => c.Type == "iss");
            if (issClaim != null && issClaim.Any())
            {
                iss = issClaim.First().Value;
            }

            if (!string.IsNullOrEmpty(iss) && iss.StartsWith("https://login.microsoftonline.com"))
            {
                var emailClaim = jwtToken.Claims.Where(c => c.Type == "email");
                if (emailClaim != null && emailClaim.Any())
                {
                    string email = emailClaim.First().Value;
                    if (!string.IsNullOrEmpty(email))
                    {
                        Console.WriteLine("Entra ID");
                        Console.WriteLine("username = " + email);
                        claims.Add(new Claim("userName", email));
                    }
                }
            }
            else
            {
                object o;
                if (jwtToken.Header.TryGetValue("x5c", out o))
                {
                    if (o is JArray)
                    {
                        string[] x5c = (o as JArray).ToObject<string[]>();

                        if (x5c != null)
                        {
                            claims.Add(new Claim("certificate", x5c[0]));
                        }
                    }
                }

                Console.WriteLine("ssiInvitation");
                if (jwtToken.Header.TryGetValue("ssiInvitation", out o))
                {
                    if (o is string s)
                    {
                        if (s != null && s != "")
                        {
                            Console.WriteLine("ssiURL = " + s);

                            string email = "";

                            // Verifier verifier = new Verifier("http://192.168.178.33:5000"); //OpenId Server
                            Verifier verifier = new Verifier(s + ":5000"); //OpenId Server

                            Dictionary<string, string> attributes = verifier.GetVerifiedAttributes(s);
                            foreach (var item in attributes)
                            {
                                Console.WriteLine(item.Key + ":" + item.Value); // OpenId Server responds with verified attributes
                                if (item.Key == "email")
                                    email = item.Value;
                            }

                            claims.Add(new Claim("userName", email));
                            Console.WriteLine("username = " + email);
                            foundUserName = true;
                        }
                    }
                }
                if (!foundUserName)
                {
                    Console.WriteLine("jwtToken email");
                    if (jwtToken.Payload.TryGetValue("email", out o))
                    {
                        if (o is string s)
                        {
                            if (s != null && s != "")
                            {
                                claims.Add(new Claim("userName", s.ToLower()));
                                Console.WriteLine("username = " + s.ToLower());
                                foundUserName = true;
                            }
                        }
                    }
                }
                if (!foundUserName)
                {
                    Console.WriteLine("jwtToken x5c");
                    if (jwtToken.Header.TryGetValue("x5c", out o))
                    {
                        if (o is JArray)
                        {
                            string[] x5c = (o as JArray).ToObject<string[]>();

                            if (x5c != null)
                            {
                                Byte[] certFileBytes = Convert.FromBase64String(x5c[0]);
                                Console.WriteLine("x509");
                                var x509 = new X509Certificate2(certFileBytes);
                                Console.WriteLine("x509 loaded");
                                string emailName = x509.GetNameInfo(X509NameType.EmailName, false);
                                if (!string.IsNullOrEmpty(emailName))
                                {
                                    Console.WriteLine("emailName");
                                    Console.WriteLine("username = " + emailName);
                                    claims.Add(new Claim("userName", emailName));
                                    foundUserName = true;
                                }
                                if (!foundUserName)
                                {
                                    Console.WriteLine("extension");
                                    foreach (X509Extension extension in x509.Extensions)
                                    {
                                        // Create an AsnEncodedData object using the extensions information.
                                        AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                                        string f = asndata.Format(true);
                                        if (f != null)
                                        {
                                            f = f.ToLower();
                                            if (f.Contains("rfc822-name="))
                                            {
                                                // RFC822-Name=christian.barth@festo.com
                                                Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
                                                Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
                                                Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
                                                Console.WriteLine(asndata.Format(true));

                                                f.Replace("\r", "");
                                                string[] split = f.Split('\n');
                                                foreach (string s in split)
                                                {
                                                    if (s.Contains("rfc822-name="))
                                                    {
                                                        emailName = s.Replace("rfc822-name=", "");
                                                        Console.WriteLine("emailName");
                                                        Console.WriteLine("username = " + emailName);
                                                        claims.Add(new Claim("userName", emailName));
                                                        foundUserName = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if (!foundUserName)
                                {
                                    if (x509.Issuer.ToLower().Contains("phoenix contact"))
                                    {
                                        Console.WriteLine("phoenix");
                                        string subject = x509.Subject.Substring(4);
                                        string[] split1 = subject.Split("(");
                                        if (split1.Length == 2)
                                        {
                                            string[] split2 = split1[0].Split(",");
                                            if (split2.Length == 2)
                                            {
                                                string email = split2[1].Substring(1, 1) + split2[0] + "@phoenixcontact.com";
                                                email = email.ToLower();
                                                email = email.Replace("ä", "ae");
                                                email = email.Replace("ö", "oe");
                                                email = email.Replace("ü", "ue");
                                                email = email.Replace("ß", "ss");
                                                claims.Add(new Claim("userName", email));
                                                Console.WriteLine("username = " + email);
                                                foundUserName = true;
                                            }
                                        }
                                    }
                                }
                                if (!foundUserName)
                                {
                                    if (x509.Issuer.ToLower().Contains("bosch"))
                                    {
                                        Console.WriteLine("bosch");
                                        string subject = x509.Subject.Substring(3);
                                        string[] split1 = subject.Split(",");
                                        string email = split1[0] + "@de.bosch.com";
                                        email = email.ToLower();
                                        claims.Add(new Claim("userName", email));
                                        Console.WriteLine("username = " + email);
                                        foundUserName = true;
                                    }
                                }
                                if (!foundUserName)
                                {
                                    if (x509.Issuer.ToLower().Contains("festo"))
                                    {
                                        Console.WriteLine("festo");
                                        Console.WriteLine("X509 with festo");
                                        string email = "";
                                        string subject = x509.Subject;
                                        if (subject != null && subject.Length >= 3)
                                        {
                                            subject = x509.Subject.Substring(3);
                                            Console.WriteLine("with subject");
                                            email = subject + "@de.festo.com";
                                            email = email.ToLower();
                                        }
                                        else
                                        {
                                            Console.WriteLine("no subject");
                                            foreach (X509Extension extension in x509.Extensions)
                                            {
                                                // Create an AsnEncodedData object using the extensions information.
                                                AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                                                Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
                                                Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
                                                Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
                                                Console.WriteLine(asndata.Format(true));

                                                string f = asndata.Format(true);
                                                if (f != null)
                                                {
                                                    f = f.ToLower();
                                                    if (f.Contains("rfc822-name=") || f.Contains("email:"))
                                                    {
                                                        f.Replace("\r", "");
                                                        string[] split = f.Split('\n');
                                                        foreach (string s in split)
                                                        {
                                                            Console.WriteLine("split: " + s);
                                                            if (s.Contains("rfc822-name="))
                                                            {
                                                                var s2 = s.Split("rfc822-name=");
                                                                if (s2.Length > 0)
                                                                {
                                                                    var e = s2[s2.Length - 1];
                                                                    email = e.Replace("festo.com", "de.festo.com");
                                                                }
                                                            }
                                                            if (s.Contains("email:"))
                                                            {
                                                                var s2 = s.Split("email:");
                                                                if (s2.Length > 0)
                                                                {
                                                                    var e = s2[s2.Length - 1];
                                                                    email = e.Replace("festo.com", "de.festo.com");
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Console.WriteLine("username = " + email);
                                        claims.Add(new Claim("userName", email));
                                        foundUserName = true;
                                    }
                                }
                            }
                        }
                    }
                }
                //// Add claims for indirect singing of policies for the requested resource
                //// More details here: https://github.com/boschresearch/py-cx-ids/tree/main/pycxids/ptt#via-daps
                if (jwtToken.Payload.TryGetValue("policy", out o))
                {
                    if (o is string s)
                    {
                        if (s != null && s != "")
                        {
                            claims.Add(new Claim("policy", s));
                            Console.WriteLine("policy = " + s);
                        }
                    }
                }
                if (jwtToken.Payload.TryGetValue("policyRequestedResource", out o))
                {
                    if (o is string s)
                    {
                        if (s != null && s != "")
                        {
                            claims.Add(new Claim("policyRequestedResource", s));
                            Console.WriteLine("policyRequestedResource = " + s);
                        }
                    }
                }
            }

            //// claims.Add(new Claim("userName", "aorzelski@phoenixcontact.com"));
            var certName = Environment.GetEnvironmentVariable("RSACERT");
            if (string.IsNullOrEmpty(certName))
            {
                certName = "identityserver.test.rsa";
            }
            claims.Add(new Claim("serverName", certName));

            // iat claim as required by JWT profile
            claims.Add(new Claim(JwtClaimTypes.IssuedAt, Clock.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64));

            var issuer = ContextAccessor.HttpContext.GetIdentityServerIssuerUri();
            var token = new Token(OidcConstants.TokenTypes.AccessToken)
            {
                CreationTime = Clock.UtcNow.UtcDateTime,
                Issuer = issuer,
                Lifetime = request.ValidatedRequest.AccessTokenLifetime,
                Claims = claims.Distinct(new ClaimComparer()).ToList(),
                ClientId = request.ValidatedRequest.Client.ClientId,
                Description = request.Description,
                AccessTokenType = request.ValidatedRequest.AccessTokenType,
                AllowedSigningAlgorithms = request.ValidatedResources.Resources.ApiResources.FindMatchingSigningAlgorithms()
            };

            // add aud based on ApiResources in the validated request
            foreach (var aud in request.ValidatedResources.Resources.ApiResources.Select(x => x.Name).Distinct())
            {
                token.Audiences.Add(aud);
            }

            if (Options.EmitStaticAudienceClaim)
            {
                token.Audiences.Add(string.Format(IdentityServerConstants.AccessTokenAudience, issuer.EnsureTrailingSlash()));
            }

            // add cnf if present
            if (request.ValidatedRequest.Confirmation.IsPresent())
            {
                token.Confirmation = request.ValidatedRequest.Confirmation;
            }
            else
            {
                if (Options.MutualTls.AlwaysEmitConfirmationClaim)
                {
                    var clientCertificate = await ContextAccessor.HttpContext.Connection.GetClientCertificateAsync();
                    if (clientCertificate != null)
                    {
                        token.Confirmation = clientCertificate.CreateThumbprintCnf();
                    }
                }
            }
            
            return token;
        }

        /// <summary>
        /// Creates a serialized and protected security token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>
        /// A security token in serialized form
        /// </returns>
        /// <exception cref="System.InvalidOperationException">Invalid token type.</exception>
        public virtual async Task<string> CreateSecurityTokenAsync(Token token)
        {
            string tokenResult;

            if (token.Type == OidcConstants.TokenTypes.AccessToken)
            {
                if (token.AccessTokenType == AccessTokenType.Jwt)
                {
                    Logger.LogTrace("Creating JWT access token");

                    tokenResult = await CreationService.CreateTokenAsync(token);
                }
                else
                {
                    Logger.LogTrace("Creating reference access token");

                    var handle = await ReferenceTokenStore.StoreReferenceTokenAsync(token);

                    tokenResult = handle;
                }
            }
            else if (token.Type == OidcConstants.TokenTypes.IdentityToken)
            {
                Logger.LogTrace("Creating JWT identity token");

                tokenResult = await CreationService.CreateTokenAsync(token);
            }
            else
            {
                throw new InvalidOperationException("Invalid token type.");
            }

            return tokenResult;
        }
    }
}
