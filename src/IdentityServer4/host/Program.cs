// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using Microsoft.Extensions.Primitives;

namespace IdentityServerHost
{
    public class Program
    {
        public static int Main(string[] args)
        {
            Console.Title = "IdentityServer4";
			// OZ
            Console.WriteLine("Security 1 Startup - Server");
            Console.WriteLine("Security 1.1 Load X509 Root Certificates into X509 Store Root");

            X509Store root = new X509Store("Root", StoreLocation.CurrentUser);
            root.Open(OpenFlags.ReadWrite);

            System.IO.DirectoryInfo ParentDirectory = new System.IO.DirectoryInfo(".");

            foreach (System.IO.FileInfo f in ParentDirectory.GetFiles("./root/*.cer"))
            {
                X509Certificate2 cert = new X509Certificate2("./root/" + f.Name);

                root.Add(cert);
                Console.WriteLine("Security 1.1 Add " + f.Name);

                IdentityServer4.ResponseHandling.DiscoveryResponseGenerator.RootCertSubjects.Add(cert.Subject);
            }

            Directory.CreateDirectory("./temp");
            // OZ end

            Activity.DefaultIdFormat = ActivityIdFormat.W3C;

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                .Enrich.FromLogContext()
                //.WriteTo.File(@"identityserver4_log.txt")
                // uncomment to write to Azure diagnostics stream
                //.WriteTo.File(
                //    @"D:\home\LogFiles\Application\identityserver.txt",
                //    fileSizeLimitBytes: 1_000_000,
                //    rollOnFileSizeLimit: true,
                //    shared: true,
                //    flushToDiskInterval: TimeSpan.FromSeconds(1))
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateLogger();

            try
            {
                Log.Information("Starting host...");
                CreateHostBuilder(args).Build().Run();
                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly.");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilog()
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}