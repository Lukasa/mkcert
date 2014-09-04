package main

import (
	"github.com/Lukasa/trustdeck/certs"
	"log"
	"net/http"
	"runtime"
)

const CERT_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

var certificates certs.CertMap = nil

func updateCertificates() {
	ignoreList := map[string]interface{}{}

	// Now, grab the certificates.
	resp, err := http.Get(CERT_URL)
	if err != nil {
		log.Fatalf("Unable to get cert file: %s", err)
	}

	_, _, objects := certs.ParseInput(resp.Body)
	resp.Body.Close()

	certificates = certs.OutputTrustedCerts(objects, ignoreList)
}

func serveCertificates(w http.ResponseWriter, r *http.Request) {
	certs.WriteCerts(w, certificates)
}

func main() {
	// Before we do anything, TURN ON THE CPUS.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// At start of day, populate the certificates.
	updateCertificates()

	// Start the HTTP server.
	http.HandleFunc("/", serveCertificates)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
