## About this fork

![Build-and-publish-docker-images-workflow](
https://github.com/admin-shell-io/aasx-IdentityServer4/workflows/Build-and-publish-docker-images-workflow/badge.svg
)

This is a fork of https://github.com/IdentityServer/IdentityServer4. The latest original commit of this fork is 
[e70eac45b8ae8cf5b4e8c75496005c7198387ee3](
https://github.com/IdentityServer/IdentityServer4/commit/e70eac45b8ae8cf5b4e8c75496005c7198387ee3
).
See [ChangesMade](https://github.com/admin-shell-io/aasx-IdentityServer4/blob/master/ChangesMade) for the applied specific changes.

IdentityServer4 already included ConsolePrivateKeyJwtClient, but this standard client only included a single certificate.
This was extended by the Industrie 4.0 certificate chain. By JWT and X5C this certificate chain is transmitted to the IdentityServer4.
The certificate chain is checked against root-certifcates which are loaded at startup from the /root directory.
The signature of the JWT is also checked by the just transmitted user certificate as part of the chain.
See admin-shell-io.com/screencast with a running demo.

There is no specific release published. Please compile with [`build.sh`](build.sh) or [`build.ps1`](build.ps1) yourself.

### Docker Image

For your convenience we provide docker images built and published automatically on every push to 
the master branch of this forked repository.
The images are available on DockerHub: https://hub.docker.com/repository/docker/adminshellio/aasx-identity-server4

Pull the latest image from the repository first:
```
docker pull adminshellio/aasx-identity-server4
```

Then run the docker:
```
docker run \
    --detach \
    --network host \
    --volume /path/to/certificate.pfx:/aasx-IdentityServer4/certificate.pfx \
    adminshellio/aasx-identity-server4
```

Mind that you have to mount your PFX certificate to the container's `/aasx-IdentityServer4/certificate.pfx`. 
(The path on the host must be an absolute one. Otherwise, the docker will silently ignore the volume!)

The password for the certificate is hard-coded to `i40`. For further hard-coded settings, see 
[`src/IdentityServer4/host/appsettings.json`](src/IdentityServer4/host/appsettings.json).

The image is set to run on ports 50000 and 50001, respectively. If you need different ports, you can set them in
`docker run`:

```
docker run \
    --detach \
    --network host \
    --volume /path/to/certificate.pfx:/aasx-IdentityServer4/certificate.pfx \
    -p 12345:50000 \
    -p 54321:50001 \
    adminshellio/aasx-identity-server4
```
where `12345` and `54321` are host's ports.

An example IdentityServer4 is running on https://admin-shell-io.com:50001/.well-known/openid-configuration.

Take also a look on the Security demo on http://admin-shell-io.com/screencasts/. An authentication flow together with AASX Package Explorer and an AAS download from an AASX Server are shown in that demo. (Remark: the screencast will be updated to the actual extended implementation soon.)

## About IdentityServer4
[<img align="right" width="100px" src="https://dotnetfoundation.org/img/logo_big.svg" />](https://dotnetfoundation.org/projects?searchquery=IdentityServer&type=project)

IdentityServer is a free, open source [OpenID Connect](http://openid.net/connect/) and [OAuth 2.0](https://tools.ietf.org/html/rfc6749) framework for ASP.NET Core.
Founded and maintained by [Dominick Baier](https://twitter.com/leastprivilege) and [Brock Allen](https://twitter.com/brocklallen), IdentityServer4 incorporates all the protocol implementations and extensibility points needed to integrate token-based authentication, single-sign-on and API access control in your applications.
IdentityServer4 is officially [certified](https://openid.net/certification/) by the [OpenID Foundation](https://openid.net) and thus spec-compliant and interoperable.
It is part of the [.NET Foundation](https://www.dotnetfoundation.org/), and operates under their [code of conduct](https://www.dotnetfoundation.org/code-of-conduct). It is licensed under [Apache 2](https://opensource.org/licenses/Apache-2.0) (an OSI approved license).

For project documentation, please visit [readthedocs](https://identityserver4.readthedocs.io).

[![Build Status](https://dev.azure.com/netidentity/IdentityServer/_apis/build/status/IdentityServer4?branchName=main)](https://dev.azure.com/netidentity/IdentityServer/_build/latest?definitionId=1&branchName=main)
[![Documentation Status](https://readthedocs.org/projects/identityserver4/badge/?version=latest)](http://docs.identityserver.io/en/latest/?badge=latest)

## Branch structure
Active development happens on the main branch. This always contains the latest version. Each (pre-) release is tagged with the corresponding version. The [aspnetcore1](https://github.com/IdentityServer/IdentityServer4/tree/aspnetcore1) and [aspnetcore2](https://github.com/IdentityServer/IdentityServer4/tree/aspnetcore2) branches contain the latest versions of the older ASP.NET Core based versions.

## How to build

* [Install](https://www.microsoft.com/net/download/core#/current) the latest .NET Core 3.1 SDK
* Install Git
* Run `build.ps1` or `build.sh` in the root of the repo

## Documentation
For project documentation, please visit [readthedocs](https://identityserver4.readthedocs.io).

See [here](http://docs.identityserver.io/en/aspnetcore1/) for the 1.x docs, and [here](http://docs.identityserver.io/en/aspnetcore2/) for the 2.x docs.

## Bug reports and feature requests
Please use the [issue tracker](https://github.com/IdentityServer/IdentityServer4/issues) for that. We only support the latest version for free. For older versions, you can get a commercial support agreement with us.

## Commercial and Community Support
If you need help with implementing IdentityServer4 or your security architecture in general, there are both free and commercial support options.
See [here](https://identityserver4.readthedocs.io/en/latest/intro/support.html) for more details.

## Sponsorship
If you are a fan of the project or a company that relies on IdentityServer, you might want to consider sponsoring.
This will help us devote more time to answering questions and doing feature development. If you are interested please head to our [Patreon](https://www.patreon.com/identityserver) page which has further details.

### Platinum Sponsors
[<img src="https://user-images.githubusercontent.com/1454075/62819413-39550c00-bb55-11e9-8f2f-a268c3552c71.png" width="200">](https://udelt.no)

[<img src="https://user-images.githubusercontent.com/1454075/66454740-fb973580-ea68-11e9-9993-6c1014881528.png" width="200">](https://github.com/dotnet-at-microsoft)

### Corporate Sponsors
[Ritter Insurance Marketing](https://www.ritterim.com)  
[ExtraNetUserManager](https://www.extranetusermanager.com/)  
[Knab](https://www.knab.nl/)

You can see a list of our current sponsors [here](https://github.com/IdentityServer/IdentityServer4/blob/main/SPONSORS.md) - and for companies we have some nice advertisement options as well.

## Acknowledgements
IdentityServer4 is built using the following great open source projects and free services:

* [ASP.NET Core](https://github.com/dotnet/aspnetcore)
* [Bullseye](https://github.com/adamralph/bullseye)
* [SimpleExec](https://github.com/adamralph/simple-exec)
* [MinVer](https://github.com/adamralph/minver)
* [Json.Net](http://www.newtonsoft.com/json)
* [XUnit](https://xunit.github.io/)
* [Fluent Assertions](http://www.fluentassertions.com/)
* [GitReleaseManager](https://github.com/GitTools/GitReleaseManager)

..and last but not least a big thanks to all our [contributors](https://github.com/IdentityServer/IdentityServer4/graphs/contributors)!
