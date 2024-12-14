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
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Lukasa/mkcert/certs"
)

const CERT_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

// We want to enable certificate pinning to a specific hash of the Mozilla
// cert. However, Go doesn't make this available to us by default. For this
// reason, we are actually going to create a custom dialer and do the
// validation there.
// This isn't very general, it hardcodes the certificate hash. This hash needs
// recalculating if Mozilla change their certificate.
var MOZILLA_CERT_HASH = []byte{
	0xce, 0xa6, 0x59, 0xb0, 0xfb, 0xe7, 0x52, 0xbe, 0xd1, 0x3a, 0xbb, 0x53,
	0x19, 0x34, 0x5b, 0x2f, 0xad, 0x16, 0x2d, 0x17, 0x3a, 0x34, 0x57, 0xe3,
	0x18, 0x99, 0xd9, 0xeb, 0xf2, 0x47, 0xa4, 0x35,
}

func pinDialer(network, addr string) (net.Conn, error) {
	conn, err := tls.Dial(network, addr, &tls.Config{})
	if err != nil {
		return conn, err
	}

	connectionState := conn.ConnectionState()
	validPin := false

	// I don't know what order the certs are in here, or if it's well defined.
	// The docs don't say, so let's just always check the whole chain.
	for _, cert := range connectionState.PeerCertificates {
		certBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			log.Fatal(err)
		}

		hash := sha256.Sum256(certBytes)
		if bytes.Compare(hash[:], MOZILLA_CERT_HASH) == 0 {
			validPin = true
		}
	}

	if !validPin {
		log.Print("No cert found matching pin.")
		return nil, errors.New("No valid pin found.")
	}

	return conn, nil
}

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
var certificates certs.CertList = nil
var certMapLock *sync.RWMutex = new(sync.RWMutex)

type CertificateList struct {
	Certificates []string
}

func updateCertificates() {
	// Build a client that checks for pinned certs.
	client := &http.Client{}
	client.Transport = &http.Transport{DialTLS: pinDialer}

	// Now, grab the certificates.
	resp, err := client.Get(CERT_URL)
	if err != nil {
		log.Fatalf("Unable to get cert file: %s", err)
	}

	_, _, objects := certs.ParseInput(resp.Body)
	resp.Body.Close()

	certMapLock.Lock()
	certificates = certs.OutputTrustedCerts(objects)
	certMapLock.Unlock()
}

// certUpdateLoop spins in a loop updating the certificates once a day.
func certUpdateLoop() {
	for {
		updateCertificates()
		<-time.After(24 * time.Hour)
	}
}

// Parses the exceptions from the path.
func getExceptionsFromPath(path string, prefix string) map[string]interface{} {
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

// Parses the exceptions from a JSON-encoded body.
func getExceptionsFromBody(r *http.Request) (map[string]interface{}, error) {
	// If there's no body immediately return an empty map.
	exceptions := make(map[string]interface{})

	if r.ContentLength == 0 {
		return exceptions, nil
	}

	// Decode the JSON from the body.
	decoder := json.NewDecoder(r.Body)
	var listExceptions []string

	err := decoder.Decode(&listExceptions)
	if err != nil && err != io.EOF {
		return exceptions, err
	}

	for _, exception := range listExceptions {
		exceptions[exception] = nil
	}

	return exceptions, nil
}

// serveBlacklistCertificates serves certificates using a blacklist. The
// expected form of the URL is: /generate/all/except/. We expect a request
// body that contains a JSON list of exact labels to exclude.
func serveBlacklistCertificates(w http.ResponseWriter, r *http.Request) {
	exceptions, err := getExceptionsFromBody(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "inline; filename=\"certs.pem\"")

	certMapLock.RLock()
	certs.WriteCerts(w, certificates, certs.BlacklistMatcher(exceptions))
	certMapLock.RUnlock()
}

// serveWhitelistCertificates serves certificates using a whitelist. The
// expected form of the URL is: /generate/. We expect a request body that
// contains a JSON list of exact labels to include
func serveWhitelistCertificates(w http.ResponseWriter, r *http.Request) {
	exceptions, err := getExceptionsFromBody(r)
	if err != nil {
		log.Printf("Bad request: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "inline; filename=\"certs.pem\"")

	certMapLock.RLock()
	certs.WriteCerts(w, certificates, certs.WhitelistMatcher(exceptions))
	certMapLock.RUnlock()
}

// serveFuzzyWhitelistCertificates serves certificates using a whitelist. The
// expected form of the URL is /generate/name1+name2+name3, where name1 and
// friends are the labels to include in the list.
//
// This uses fuzzy matching: specifically, if any of the label fragments
// passed appear in the label then a cert will be considered to match. This is
// not secure but is clean. Verify the output you get!
func serveFuzzyWhitelistCertificates(w http.ResponseWriter, r *http.Request) {
	exceptionsMap := getExceptionsFromPath(r.URL.Path, "/generate/")
	exceptions := make([]string, 0, len(exceptionsMap))
	for k, _ := range exceptionsMap {
		exceptions = append(exceptions, k)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "inline; filename=\"certs.pem\"")

	certMapLock.RLock()
	certs.WriteCerts(w, certificates, certs.SubstringWhitelistMatcher(exceptions))
	certMapLock.RUnlock()
}

// serveFuzzyBlacklistCertificates serves certificates using a blacklist. The
// expected form of the URL is /generate/all/except/name1+name2+name3, where
// name1 and friends are the labels to exclude from the list.
//
// This uses fuzzy matching: specifically, if any of the label fragments
// passed appear in the label then a cert will be considered to match. This is
// not secure but is clean. Verify the output you get!
func serveFuzzyBlacklistCertificates(w http.ResponseWriter, r *http.Request) {
	exceptionsMap := getExceptionsFromPath(r.URL.Path, "/generate/all/except/")
	exceptions := make([]string, 0, len(exceptionsMap))
	for k, _ := range exceptionsMap {
		exceptions = append(exceptions, k)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "inline; filename=\"certs.pem\"")

	certMapLock.RLock()
	certs.WriteCerts(w, certificates, certs.SubstringBlacklistMatcher(exceptions))
	certMapLock.RUnlock()
}

// whitelist is the response handler for the /generate/ URL endpoint. It
// handles the various requests that can be made to that endpoint.
func whitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		serveFuzzyWhitelistCertificates(w, r)
	case "POST":
		serveWhitelistCertificates(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// blacklist is the response handler for the /generate/all/except/ URL
// endpoint. It handles the various requests that can be made to that endpoint.
func blacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		serveFuzzyBlacklistCertificates(w, r)
	case "POST":
		serveBlacklistCertificates(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
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

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%v", len(b)))
	w.Write(b)
}

func main() {
	// Start the certificate update loop.
	go certUpdateLoop()

	// Start the HTTP server.
	http.HandleFunc("/labels/", listAllCerts)
	http.HandleFunc("/generate/", whitelist)
	http.HandleFunc("/generate/all/except/", blacklist)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
