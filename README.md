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

### /generate/<certs>

Builds a PEM file containing only the root certificates specified. The format
of `<certs>` is a `+`-separated string. Therefore, to build a `.pem` file that
contains "GeoTrust Global CA" and "QuoVadis Root CA", you would issue a GET
request to `/generate/GeoTrust%20Global%20CA+QuoVadis%20Root%20CA`.

The response to this request has the body formatted exactly like a `.pem` file,
suitable for saving immediately.

### /generate/all/except/<certs>

Builds a PEM file containing all root certificates *except* the root
certificates specified. The format of `<certs>` is a `+`-separated string.
Therefore, to build a `.pem` file that contains everything but
"GeoTrust Global CA" and "QuoVadis Root CA", you would issue a GET request to
`/generate/all/except/GeoTrust%20Global%20CA+QuoVadis%20Root%20CA`.

The response to this request has the body formatted exactly like a `.pem` file,
suitable for saving immediately.

## License

mkcert.org is made available under the Apache 2.0 License. See LICENSE for more
details.
