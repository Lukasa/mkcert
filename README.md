# Mkcert

mkcert.org is a web service that allows you to build customised TLS trust
stores.

Currently mkcert is just an API with no pretty frontend. That's in the works.

## API

mkcert has the following endpoints:

### /labels/

Returns a JSON object containing one key (`Certificates`) whose value is a list
of all the certificate labels in the default trust store. Each of the items in
the list can be passed to the other API endpoints to refer to a certificate.

### GET /generate/<certs>

Builds a PEM file containing only the root certificates specified. The format
of `<certs>` is a `+`-separated string. This string will be used to perform
'fuzzy-ish' matching to certificate labels. For example, if one of your
`<certs>` strings is `comodo`, any label that contains the sequence of
characters `comodo` (case-insensitively) will match.

Therefore, to build a `.pem` file that contains any GeoTrust certificate and
any QuoVadis certificate, you would issue a GET request to
`/generate/geotrust+quovadis`

The response to this request has the body formatted exactly like a `.pem` file,
suitable for saving immediately.

### GET /generate/all/except/<certs>

Builds a PEM file containing all root certificates *except* the root
certificates specified. The format of `<certs>` is a `+`-separated string.
This string will be used to perform 'fuzzy-ish' mapping to certificate labels.
For example, if one of your `<certs>` strings is `comodo`, any label that
contains the sequence of characters `comodo` (case-insensitively) will match.

Therefore, to build a `.pem` file that contains everything but any GeoTrust
certificates and any QuoVadis certificates, you would issue a GET request to
`/generate/all/except/geotrust+quovadis`.

The response to this request has the body formatted exactly like a `.pem` file,
suitable for saving immediately.

### POST /generate/

Builds a PEM file containing only the root certificates specified. The root
certs are specified in the request body. The format of the request body is a
JSON list of *exact* labels to include. That is, to generate a `.pem` file
that contains only the "GeoTrust Global CA" and the "QuoVadis Root CA", you
would POST the following body:

    ["GeoTrust Global CA", "QuoVadis Root CA"]

The response to this request has the body formatted exactly like a `.pem` file,
suitable for saving immediately.

### POST /generate/all/except/

Builds a PEM file containing all but the root certificates specified. The root
certs are specified in the request body. The format of the request body is a
JSON list of *exact* labels to include. That is, to generate a `.pem` file
that contains all the certs except the "GeoTrust Global CA" and the "QuoVadis
Root CA", you would POST the following body:

    ["GeoTrust Global CA", "QuoVadis Root CA"]

The response to this request has the body formatted exactly like a `.pem` file,
suitable for saving immediately.

## License

mkcert.org is made available under the Apache 2.0 License. See LICENSE for more
details.
