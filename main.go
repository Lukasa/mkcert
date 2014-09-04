package main

import (
	"github.com/Lukasa/trustdeck/certs"
	"log"
	"net/http"
	"runtime"
	"strings"
)

const CERT_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

var certificates certs.CertMap = nil

func updateCertificates() {
	// Now, grab the certificates.
	resp, err := http.Get(CERT_URL)
	if err != nil {
		log.Fatalf("Unable to get cert file: %s", err)
	}

	_, _, objects := certs.ParseInput(resp.Body)
	resp.Body.Close()

	certificates = certs.OutputTrustedCerts(objects)
}

// Parses the exceptions from the path.
func getExceptions(path string, prefix string) map[string]interface{} {
	// Remove the prefix.
	query := string(path[len(prefix):])

	// Split the query on each '+' character.
	components := strings.Split(query, "+")

	exceptions := make(map[string]interface{})
	for _, component := range components {
		exceptions[component] = nil
	}

	return exceptions
}

// serveBlacklistCertificates serves certificates using a blacklist. The
// expected form of the URL is: /generate/name1+name2+name3, where name1 and
// friends are the labels to exclude from the list.
func serveBlacklistCertificates(w http.ResponseWriter, r *http.Request) {
	exceptions := getExceptions(r.URL.Path, "/generate/")
	certs.WriteCerts(w, certificates, false, exceptions)
}

func main() {
	// Before we do anything, TURN ON THE CPUS.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// At start of day, populate the certificates.
	updateCertificates()

	// Start the HTTP server.
	http.HandleFunc("/generate/", serveBlacklistCertificates)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
