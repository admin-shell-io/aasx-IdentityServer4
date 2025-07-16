// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;

namespace IdentityServer4.Validation
{
    /// <summary>
    /// Validates a secret based on RS256 signed JWT token
    /// </summary>
    public class PrivateKeyJwtSecretValidator : ISecretValidator
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IReplayCache _replayCache;
        private readonly ILogger _logger;

        private const string Purpose = nameof(PrivateKeyJwtSecretValidator);
        
        /// <summary>
        /// Instantiates an instance of private_key_jwt secret validator
        /// </summary>
        public PrivateKeyJwtSecretValidator(IHttpContextAccessor contextAccessor, IReplayCache replayCache, ILogger<PrivateKeyJwtSecretValidator> logger)
        {
            _contextAccessor = contextAccessor;
            _replayCache = replayCache;
            _logger = logger;
        }

        /// <summary>
        /// Validates a secret
        /// </summary>
        /// <param name="secrets">The stored secrets.</param>
        /// <param name="parsedSecret">The received secret.</param>
        /// <returns>
        /// A validation result
        /// </returns>
        /// <exception cref="System.ArgumentException">ParsedSecret.Credential is not a JWT token</exception>
        public async Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets, ParsedSecret parsedSecret)
        {
            var fail = new SecretValidationResult { Success = false };
            var success = new SecretValidationResult { Success = true };

            if (parsedSecret.Type != IdentityServerConstants.ParsedSecretTypes.JwtBearer)
            {
                return fail;
            }

            if (!(parsedSecret.Credential is string jwtTokenString))
            {
                _logger.LogError("ParsedSecret.Credential is not a string.");
                return fail;
            }

            List<SecurityKey> trustedKeys;
            try
            {
                trustedKeys = await secrets.GetKeysAsync();
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Could not parse secrets");
                return fail;
            }

            if (!trustedKeys.Any())
            {
                _logger.LogError("There are no keys available to validate client assertion.");
                return fail;
            }

            var jwtToken = new JwtSecurityToken(jwtTokenString);

            // OZ

            var entraidClaim = jwtToken.Claims.Where(c => c.Type == "entraid");
            if (entraidClaim != null && entraidClaim.Any())
            {
                jwtTokenString = entraidClaim.First().Value;
                jwtToken = new JwtSecurityToken(jwtTokenString);
                Console.WriteLine("Received entraid token: " + jwtToken);
            }

            var iss = "";
            var issClaim = jwtToken.Claims.Where(c => c.Type == "iss");
            if (issClaim != null && issClaim.Any())
            {
                iss = issClaim.First().Value;
            }

            if (!string.IsNullOrEmpty(iss) && iss.StartsWith("https://login.microsoftonline.com"))
            {
                var clientId = "865f6ac0-cdbc-44c6-98cc-3e35c39ecb6e";
                var tenantId = jwtToken.Claims
                    .First(c => c.Type == "tid").Value;

                var jwksUrl = $"https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys";
                Console.WriteLine("Entra ID: " + jwksUrl);

                var trusted = false;
                if (File.Exists("./TrustedEntraIssuers.dat"))
                {
                    var lines = File.ReadLines("./TrustedEntraIssuers.dat");
                    foreach (var line in lines)
                    {
                        Console.WriteLine("Trusted: "+ line);
                        if (iss == line.Trim())
                        {
                            trusted = true;
                            Console.WriteLine("iss is trusted");
                        }
                    }
                }

                using var httpClient = new HttpClient();
                var jwksJson = httpClient.GetStringAsync(jwksUrl).Result;
                var jwks = new JsonWebKeySet(jwksJson);
                var signingKeys = jwks.GetSigningKeys();

                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = $"https://login.microsoftonline.com/{tenantId}/v2.0",
                    ValidateAudience = true,
                    ValidAudience = clientId,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = signingKeys
                };

                try
                {
                    var principal = tokenHandler.ValidateToken(jwtTokenString, validationParameters, out var validatedToken);
                    Console.WriteLine("✅ Token is valid.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Token validation failed: {ex.Message}");
                    return fail;
                }
                return success;
            }

            // var x5c = jwtToken.Payload.Claims.FirstOrDefault(c => c.Type == "x5c")?.Value;
            // string x5c = jwtToken.Header.GetValueOrDefault("x5c");
            Console.WriteLine("Client Token:\n" + jwtTokenString + "\n");

            object o;
            if (jwtToken.Header.TryGetValue("x5c", out o))
            {
                // if (o is string)
                var s = o.GetType().ToString();
                if (o is JArray)
                {
                    // string x5c = o as string;
                    string[] x5c = (o as JArray).ToObject<string[]>();

                    // if (x5c != null && x5c != "")
                    if (x5c != null)
                    {
                        // Console.WriteLine("x5c:\n" + x5c);
                        Console.WriteLine("Security 2.1a Server: x5c with certificate chain received");

                        // parsed = JObject.Parse(Jose.JWT.Payload(token));
                        // user = parsed.SelectToken("user").Value<string>();
                        // string user = jwtToken.Payload.Claims.FirstOrDefault(c => c.Type == "user")?.Value;

                        X509Store storeCA = new X509Store("CA", StoreLocation.CurrentUser);
                        storeCA.Open(OpenFlags.ReadWrite);
                        bool valid = false;

                        // string[] x5c64 = JsonConvert.DeserializeObject<string[]>(x5c);
                        string[] x5c64 = x5c;

                        X509Certificate2Collection xcc = new X509Certificate2Collection();

                        Byte[] certFileBytes = Convert.FromBase64String(x5c64[0]);
                        /*
                        string fileCert = "./temp/" + user + ".cer";
                        File.WriteAllBytes(fileCert, certFileBytes);
                        Console.WriteLine("Security 2.1b Server: " + fileCert + " received");
                        */
                        var x509 = new X509Certificate2(certFileBytes);

                        xcc.Add(x509);
                        Console.WriteLine("Security 2.1c Certificate in Chain: " + x509.Subject);

                        StringBuilder builder = new StringBuilder();
                        builder.AppendLine("-----BEGIN CERTIFICATE-----");
                        builder.AppendLine(
                            Convert.ToBase64String(x509.RawData, Base64FormattingOptions.InsertLineBreaks));
                        builder.AppendLine("-----END CERTIFICATE-----");
                        Console.WriteLine("Client Certificate: ");
                        Console.WriteLine(builder);

                        for (int i = 1; i < x5c64.Length; i++)
                        {
                            var cert = new X509Certificate2(Convert.FromBase64String(x5c64[i]));
                            Console.WriteLine("Security 2.1c Certificate in Chain: " + cert.Subject);
                            if (cert.Subject != cert.Issuer)
                            {
                                xcc.Add(cert);
                                storeCA.Add(cert);
                            }
                        }

                        X509Chain c = new X509Chain();
                        c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                        valid = c.Build(x509);

                        // storeCA.RemoveRange(xcc);
                        Console.WriteLine("Security 2.1d Server: Validate chain with root cert");

                        if (!valid)
                        {
                            Console.WriteLine("ERROR: Certificate " + x509.Subject + " not valid!");
                            _logger.LogError("Certificate " + x509.Subject + " not valid!");

                            foreach (X509ChainStatus status in c.ChainStatus)
                            {
                                Console.WriteLine($"Chain error: {status.Status} - {status.StatusInformation}");
                            }
                    
                            foreach (X509ChainElement element in c.ChainElements)
                            {
                                Console.WriteLine($"Certificate: {element.Certificate.Subject}");
                                foreach (X509ChainStatus status in element.ChainElementStatus)
                                {
                                    Console.WriteLine($"  Status: {status.Status} - {status.StatusInformation}");
                                }
                            }

                            return fail;
                        }

                        var xsk = new X509SecurityKey(x509);
                        trustedKeys = new List<SecurityKey> { xsk };
                    }
                }
            }
            // OZ end


            var validAudiences = new[]
            {
                // issuer URI (tbd)
                //_contextAccessor.HttpContext.GetIdentityServerIssuerUri(),
                
                // token endpoint URL
                string.Concat(_contextAccessor.HttpContext.GetIdentityServerIssuerUri().EnsureTrailingSlash(),
                    Constants.ProtocolRoutePaths.Token)
            };
            
            var tokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = trustedKeys,
                ValidateIssuerSigningKey = true,

                ValidIssuer = parsedSecret.Id,
                ValidateIssuer = true,

                ValidAudiences = validAudiences,
                // ValidateAudience = true,
                ValidateAudience = false,

                RequireSignedTokens = true,
                RequireExpirationTime = true,
                
                ClockSkew = TimeSpan.FromMinutes(5)
            };
            try
            {
                // OZ debug
                Console.WriteLine("ValidIssuer = " + parsedSecret.Id);
                foreach (string va in validAudiences)
                    Console.WriteLine("ValidAudiences = " + va);
                // OZ end
            
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(jwtTokenString, tokenValidationParameters, out var token);

                jwtToken = (JwtSecurityToken)token;
                if (jwtToken.Subject != jwtToken.Issuer)
                {
                    _logger.LogError("Both 'sub' and 'iss' in the client assertion token must have a value of client_id.");
                    return fail;
                }

                var exp = jwtToken.Payload.Exp;
                if (!exp.HasValue)
                {
                    _logger.LogError("exp is missing.");
                    return fail;
                }
                
                var jti = jwtToken.Payload.Jti;
                if (jti.IsMissing())
                {
                    _logger.LogError("jti is missing.");
                    return fail;
                }

                if (await _replayCache.ExistsAsync(Purpose, jti))
                {
                    _logger.LogError("jti is found in replay cache. Possible replay attack.");
                    return fail;
                }
                else
                {
                    await _replayCache.AddAsync(Purpose, jti, DateTimeOffset.FromUnixTimeSeconds(exp.Value).AddMinutes(5));
                }

                return success;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "JWT token validation error");
                return fail;
            }
        }
    }
}
