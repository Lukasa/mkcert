//  Copyright 2014 Cory Benfield
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"encoding/json"
	"github.com/Lukasa/mkcert/certs"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
)

const CERT_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

// Global state! It's evil!
//
// More seriously, this is a performance optimisation. The certificate map
// can be quite large, and copying it around is a stupid waste of everyone's
// time when 99.99% of the time we just want to read from it. Instead, we use
// a RWMutex to ensure that we can always read from this structure, but cannot
// read in the middle of a write.
//
// Arguably this is not idiomatic Go. If someone can show me an idiomatic
// approach that doesn't copy memory like a fifth-grader copies math answers,
// please let me know.
var certificates certs.CertMap = nil
var certMapLock *sync.RWMutex = new(sync.RWMutex)

type CertificateList struct {
	Certificates []string
}

func updateCertificates() {
	// Now, grab the certificates.
	resp, err := http.Get(CERT_URL)
	if err != nil {
		log.Fatalf("Unable to get cert file: %s", err)
	}

	_, _, objects := certs.ParseInput(resp.Body)
	resp.Body.Close()

	certMapLock.Lock()
	certificates = certs.OutputTrustedCerts(objects)
	certMapLock.Unlock()
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

	certMapLock.RLock()
	certs.WriteCerts(w, certificates, false, exceptions)
	certMapLock.RUnlock()
}

// serveWhitelistCertificates serves certificates using a whitelist. The
// expected form of the URL is: /generate/all/except/name1+name2+name3, where
// name1 and friends are the labels to exclude from the list.
func serveWhitelistCertificates(w http.ResponseWriter, r *http.Request) {
	exceptions := getExceptions(r.URL.Path, "/generate/all/except/")

	certMapLock.RLock()
	certs.WriteCerts(w, certificates, true, exceptions)
	certMapLock.RUnlock()
}

// listAllCerts provides a JSON object that contains a list of all the
// certificates in the bundle. Each key is a value that can be sent on the API.
func listAllCerts(w http.ResponseWriter, r *http.Request) {
	certMapLock.RLock()
	labels := certs.OutputAllLabels(certificates)
	certMapLock.RUnlock()

	b, err := json.Marshal(CertificateList{labels})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func main() {
	// Before we do anything, TURN ON THE CPUS.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// At start of day, populate the certificates.
	updateCertificates()

	// Start the HTTP server.
	http.HandleFunc("/labels/", listAllCerts)
	http.HandleFunc("/generate/", serveWhitelistCertificates)
	http.HandleFunc("/generate/all/except/", serveBlacklistCertificates)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
