#!/usr/bin/env bash

CERTIFICATE_PTH=/aasx-IdentityServer4/certificate.pfx
if [ ! -f "$CERTIFICATE_PTH" ]; then
    echo "The certificate file does not exist: ${CERTIFICATE_PTH}" 1>&2
    echo "Did you mount the file as the virtual volume in the docker or copy it with docker cp command?" 1>&2
    exit 1
fi

cd /aasx-IdentityServer4 || (echo "Could not change to /aasx-IdentityServer4" 1>&2 && exit 1)
dotnet Host.dll
