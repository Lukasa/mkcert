// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@chromium.org (Adam Langley)

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This utility parses Mozilla's certdata.txt and extracts a list of trusted
// certificates in PEM form.
//
// A current version of certdata.txt can be downloaded from:
//   https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

// This source file is a downstream modification of the above-licensed file
// for use as part of Trustdeck.
package certs

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/md5"
	"crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Object represents a collection of attributes from the certdata.txt file
// which are usually either certificates or trust records.
type Object struct {
	attrs        map[string]Attribute
	startingLine int // the line number that the object started on.
}

type Attribute struct {
	attrType string
	value    []byte
}

// Certificate is an in-memory representation of a certificate.
type Certificate struct {
	Issuer            string
	Subject           string
	Label             string
	Serial            string
	MD5Fingerprint    string
	SHA1Fingerprint   string
	SHA256Fingerprint string
	PEMBlock          *pem.Block
}

type CertList []*Certificate

type CertMatcher func(*Certificate) bool

var (
	// ignoreList maps from CKA_LABEL values (from the upstream roots file)
	// to an optional comment which is displayed when skipping matching
	// certificates.
	ignoreList map[string]string

	includedUntrustedFlag = flag.Bool("include-untrusted", false, "If set, untrusted certificates will also be included in the output")
	ignoreListFilename    = flag.String("ignore-list", "", "File containing a list of certificates to ignore")
)

// parseIgnoreList parses the ignore-list file into ignoreList
func parseIgnoreList(ignoreListFile io.Reader) {
	in := bufio.NewReader(ignoreListFile)
	var lineNo int

	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if split := strings.SplitN(line, "#", 2); len(split) == 2 {
			// this line has an additional comment
			ignoreList[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
		} else {
			ignoreList[line] = ""
		}
	}
}

// parseInput parses a certdata.txt file into it's license blob, the CVS id (if
// included) and a set of Objects.
func ParseInput(inFile io.Reader) (license, cvsId string, objects []*Object) {
	in := bufio.NewReader(inFile)
	var lineNo int

	// Discard anything prior to the license block.
	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if strings.Contains(line, "This Source Code") {
			license += line
			license += "\n"
			break
		}
	}
	if len(license) == 0 {
		log.Fatalf("Read whole input and failed to find beginning of license")
	}
	// Now collect the license block.
	// certdata.txt from hg.mozilla.org no longer contains CVS_ID.
	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if strings.Contains(line, "CVS_ID") || len(line) == 0 {
			break
		}
		license += line
		license += "\n"
	}

	var currentObject *Object
	var beginData bool

	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if strings.HasPrefix(line, "CVS_ID ") {
			cvsId = line[7:]
			continue
		}
		if line == "BEGINDATA" {
			beginData = true
			continue
		}

		words := strings.Fields(line)
		var value []byte
		if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
			startingLine := lineNo
			var ok bool
			value, ok = readMultilineOctal(in, &lineNo)
			if !ok {
				log.Fatalf("Failed to read octal value starting at line %d", startingLine)
			}
		} else if len(words) < 3 {
			log.Fatalf("Expected three or more values on line %d, but found %d", lineNo, len(words))
		} else {
			value = []byte(strings.Join(words[2:], " "))
		}

		if words[0] == "CKA_CLASS" {
			// Start of a new object.
			if currentObject != nil {
				objects = append(objects, currentObject)
			}
			currentObject = new(Object)
			currentObject.attrs = make(map[string]Attribute)
			currentObject.startingLine = lineNo
		}
		if currentObject == nil {
			log.Fatalf("Found attribute on line %d which appears to be outside of an object", lineNo)
		}
		currentObject.attrs[words[0]] = Attribute{
			attrType: words[1],
			value:    value,
		}
	}

	if !beginData {
		log.Fatalf("Read whole input and failed to find BEGINDATA")
	}

	if currentObject != nil {
		objects = append(objects, currentObject)
	}

	return
}

// GetAllLabels returns all the certificate labels from the parsed certificates.
func OutputAllLabels(certs CertList) (labels []string) {
	for _, cert := range certs {
		escapedLabel := unescapeLabel(strings.Trim(cert.Label, "\""))
		labels = append(labels, escapedLabel)
	}

	return
}

// outputTrustedCerts writes a series of PEM encoded certificates to out by
// finding certificates and their trust records in objects.
func OutputTrustedCerts(objects []*Object) (parsedCerts CertList) {
	certs := filterObjectsByClass(objects, "CKO_CERTIFICATE")
	trusts := filterObjectsByClass(objects, "CKO_NSS_TRUST")
	parsedCerts = make(CertList, 0)

	for _, cert := range certs {
		derBytes := cert.attrs["CKA_VALUE"].value
		hash := sha1.New()
		hash.Write(derBytes)
		digest := hash.Sum(nil)

		label := string(cert.attrs["CKA_LABEL"].value)

		x509, err := x509.ParseCertificate(derBytes)
		if err != nil {
			// This is known to occur because of a broken certificate in NSS.
			// https://bugzilla.mozilla.org/show_bug.cgi?id=707995
			log.Printf("Failed to parse certificate starting on line %d: %s", cert.startingLine, err)
			continue
		}

		// TODO(agl): wtc tells me that Mozilla might get rid of the
		// SHA1 records in the future and use issuer and serial number
		// to match trust records to certificates (which is what NSS
		// currently uses). This needs some changes to the crypto/x509
		// package to keep the raw names around.

		var trust *Object
		for _, possibleTrust := range trusts {
			if bytes.Equal(digest, possibleTrust.attrs["CKA_CERT_SHA1_HASH"].value) {
				trust = possibleTrust
				break
			}
		}

		if trust == nil {
			log.Fatalf("No trust found for certificate object starting on line %d (sha1: %x)", cert.startingLine, digest)
		}

		trustType := trust.attrs["CKA_TRUST_SERVER_AUTH"].value
		if len(trustType) == 0 {
			log.Fatalf("No CKA_TRUST_SERVER_AUTH found in trust starting at line %d", trust.startingLine)
		}

		var trusted bool
		switch string(trustType) {
		case "CKT_NSS_NOT_TRUSTED":
			// An explicitly distrusted cert
			trusted = false
		case "CKT_NSS_TRUSTED_DELEGATOR":
			// A cert trusted for issuing SSL server certs.
			trusted = true
		case "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_MUST_VERIFY_TRUST":
			// A cert not trusted for issuing SSL server certs, but is trusted for other purposes.
			trusted = false
		default:
			log.Fatalf("Unknown trust value '%s' found for trust record starting on line %d", trustType, trust.startingLine)
		}

		if !trusted {
			continue
		}

		block := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}

		parsedCert := &Certificate{
			nameToString(x509.Issuer),
			nameToString(x509.Subject),
			label,
			x509.SerialNumber.String(),
			fingerprintString(crypto.MD5, x509.Raw),
			fingerprintString(crypto.SHA1, x509.Raw),
			fingerprintString(crypto.SHA256, x509.Raw),
			block,
		}
		parsedCerts = append(parsedCerts, parsedCert)
	}

	return
}

// WhitelistMatcher builds a matching function that only emits certificates
// that are in the whitelist.
func WhitelistMatcher(whitelist map[string]interface{}) CertMatcher {
	return func(c *Certificate) bool {
		escapedLabel := unescapeLabel(strings.Trim(c.Label, "\""))
		if _, present := whitelist[escapedLabel]; present {
			return true
		} else {
			return false
		}
	}
}

// BlacklistMatcher builds a matching function that only emits certificates
// that are not in the blacklist.
func BlacklistMatcher(blacklist map[string]interface{}) CertMatcher {
	return func(c *Certificate) bool {
		escapedLabel := unescapeLabel(strings.Trim(c.Label, "\""))
		if _, present := blacklist[escapedLabel]; present {
			return false
		} else {
			return true
		}
	}
}

// SubstringWhitelistMatcher builds a matching function that emits certificates
// when the all-lowercase label contains any of the all-lowercase whitelist,
// and otherwise does not emit a certificate. This allows for strings like
// 'comodo' to match all comodo certificates while not matching others.
//
// This is not the most secure way to match certificates! Verify the output.
func SubstringWhitelistMatcher(whitelist []string) CertMatcher {
	// Normalise the whitelist
	internal_whitelist := make([]string, len(whitelist))
	for i, val := range whitelist {
		internal_whitelist[i] = strings.ToLower(val)
	}

	return func(c *Certificate) bool {
		escapedLabel := unescapeLabel(strings.Trim(c.Label, "\""))
		normalisedLabel := strings.ToLower(escapedLabel)

		for _, label := range internal_whitelist {
			if strings.Contains(normalisedLabel, label) {
				return true
			}
		}

		return false
	}
}

// SubstringBlacklistMatcher builds a matching function that emits certificates
// when the all-lowercase label contains any of the all-lowercase blacklist,
// and otherwise does not emit a certificate. This allows for strings like
// 'comodo' to match all comodo certificates while not matching others.
//
// This is not the most secure way to match certificates! Verify the output.
func SubstringBlacklistMatcher(blacklist []string) CertMatcher {
	// Normalise the blacklist
	internal_blacklist := make([]string, len(blacklist))
	for i, val := range blacklist {
		internal_blacklist[i] = strings.ToLower(val)
	}

	return func(c *Certificate) bool {
		escapedLabel := unescapeLabel(strings.Trim(c.Label, "\""))
		normalisedLabel := strings.ToLower(escapedLabel)

		for _, label := range internal_blacklist {
			if strings.Contains(normalisedLabel, label) {
				return false
			}
		}

		return true
	}
}

// WriteCerts writes certificates out if they match a specific filter criteria.
func WriteCerts(out io.Writer, certs CertList, matcher CertMatcher) {
	for _, cert := range certs {
		if !matcher(cert) {
			log.Printf("Skipping certificate %s", cert.Label)
			continue
		}

		io.WriteString(out, "\n")

		io.WriteString(out, "# Issuer: "+cert.Issuer+"\n")
		io.WriteString(out, "# Subject: "+cert.Subject+"\n")
		io.WriteString(out, "# Label: "+cert.Label+"\n")
		io.WriteString(out, "# Serial: "+cert.Serial+"\n")
		io.WriteString(out, "# MD5 Fingerprint: "+cert.MD5Fingerprint+"\n")
		io.WriteString(out, "# SHA1 Fingerprint: "+cert.SHA1Fingerprint+"\n")
		io.WriteString(out, "# SHA256 Fingerprint: "+cert.SHA256Fingerprint+"\n")
		pem.Encode(out, cert.PEMBlock)
	}
}

// nameToString converts name into a string representation containing the
// CommonName, Organization and OrganizationalUnit.
func nameToString(name pkix.Name) string {
	ret := ""
	if len(name.CommonName) > 0 {
		ret += "CN=" + name.CommonName
	}

	if org := strings.Join(name.Organization, "/"); len(org) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "O=" + org
	}

	if orgUnit := strings.Join(name.OrganizationalUnit, "/"); len(orgUnit) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "OU=" + orgUnit
	}

	return ret
}

// filterObjectsByClass returns a subset of in where each element has the given
// class.
func filterObjectsByClass(in []*Object, class string) (out []*Object) {
	for _, object := range in {
		if string(object.attrs["CKA_CLASS"].value) == class {
			out = append(out, object)
		}
	}
	return
}

// readMultilineOctal converts a series of lines of octal values into a slice
// of bytes.
func readMultilineOctal(in *bufio.Reader, lineNo *int) ([]byte, bool) {
	var value []byte

	for line, eof := getLine(in, lineNo); !eof; line, eof = getLine(in, lineNo) {
		if line == "END" {
			return value, true
		}

		for _, octalStr := range strings.Split(line, "\\") {
			if len(octalStr) == 0 {
				continue
			}
			v, err := strconv.ParseUint(octalStr, 8, 8)
			if err != nil {
				log.Printf("error converting octal string '%s' on line %d", octalStr, *lineNo)
				return nil, false
			}
			value = append(value, byte(v))
		}
	}

	// Missing "END"
	return nil, false
}

// getLine reads the next line from in, aborting in the event of an error.
func getLine(in *bufio.Reader, lineNo *int) (string, bool) {
	*lineNo++
	line, isPrefix, err := in.ReadLine()
	if err == io.EOF {
		return "", true
	}
	if err != nil {
		log.Fatalf("I/O error while reading input: %s", err)
	}
	if isPrefix {
		log.Fatalf("Line too long while reading line %d", *lineNo)
	}
	return string(line), false
}

func fingerprintString(hashFunc crypto.Hash, data []byte) string {
	hash := hashFunc.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	hex := fmt.Sprintf("%x", digest)
	ret := ""
	for len(hex) > 0 {
		if len(ret) > 0 {
			ret += ":"
		}
		todo := 2
		if len(hex) < todo {
			todo = len(hex)
		}
		ret += hex[:todo]
		hex = hex[todo:]
	}

	return ret
}

func isHex(c rune) (value byte, ok bool) {
	switch {
	case c >= '0' && c <= '9':
		return byte(c) - '0', true
	case c >= 'a' && c <= 'f':
		return byte(c) - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return byte(c) - 'A' + 10, true
	}

	return 0, false
}

func appendRune(out []byte, r rune) []byte {
	if r < 128 {
		return append(out, byte(r))
	}

	var buf [utf8.UTFMax]byte
	n := utf8.EncodeRune(buf[:], r)
	return append(out, buf[:n]...)
}

// unescapeLabel unescapes "\xab" style hex-escapes.
func unescapeLabel(escaped string) string {
	var out []byte
	var last rune
	var value byte
	state := 0

	for _, r := range escaped {
		switch state {
		case 0:
			if r == '\\' {
				state++
				continue
			}
		case 1:
			if r == 'x' {
				state++
				continue
			}
			out = append(out, '\\')
		case 2:
			if v, ok := isHex(r); ok {
				value = v
				last = r
				state++
				continue
			} else {
				out = append(out, '\\', 'x')
			}
		case 3:
			if v, ok := isHex(r); ok {
				value <<= 4
				value += v
				out = append(out, byte(value))
				state = 0
				continue
			} else {
				out = append(out, '\\', 'x')
				out = appendRune(out, last)
			}
		}
		state = 0
		out = appendRune(out, r)
	}

	switch state {
	case 3:
		out = append(out, '\\', 'x')
		out = appendRune(out, last)
	case 2:
		out = append(out, '\\', 'x')
	case 1:
		out = append(out, '\\')
	}

	return string(out)
}
