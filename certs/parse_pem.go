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
package certs

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
)

var (
	InvalidCertificate error = errors.New("Invalid certificate.")
)

// DecodePEMBlock takes a single PEM file as provided by a user and decodes it into our intermediate certificate
// representation.
//
// The special function of this code is to handle the case that the user has accidentally provided us with a
// concatenated set of certificates. In this case, all certificates will be added to the trust store, with the
// label manipulated slightly to distinguish between them.
func DecodePEMBlock(data []byte, label string) ([]*Certificate, error) {
	// Step one, decode the PEM file into all its constituent parts.
	blocks := make([]*pem.Block, 0)
	var p *pem.Block

	for data != nil && len(data) > 0 {
		p, data = pem.Decode(data)
		if p == nil {
			log.Println("Invalid PEM file.")
			return nil, InvalidCertificate
		}
		blocks = append(blocks, p)
	}

	// Check whether we have multiple. If we do, fill out a slice of labels for each: otherwise,
	// create the slice with one element containing only the requested label.
	labels := make([]string, 0, len(blocks))

	if len(blocks) > 1 {
		for i := 1; i <= len(blocks); i++ {
			labels = append(labels, fmt.Sprintf("%v %v", label, i))
		}
	} else {
		labels = append(labels, label)
	}

	// Now, for each block, parse the PEM certificate.
	parsedCerts := make([]*Certificate, 0, len(blocks))
	for i, block := range blocks {
		p, err := parsePEMCertificate(block, labels[i])
		if err != nil {
			log.Printf("Failed to parse cert %v.\n", i)
			return nil, err
		}

		parsedCerts = append(parsedCerts, p)
	}

	return parsedCerts, nil
}

func parsePEMCertificate(p *pem.Block, label string) (*Certificate, error) {
	// The decoded PEM file should be x509 data. We should therefore be able to pull that data out
	// using the x509 module.
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		log.Printf("Invalid certificate: %v.\n", err)
		return nil, InvalidCertificate
	}

	// Transform this into our internal representation.
	parsed := &Certificate{
		nameToString(c.Issuer),
		nameToString(c.Subject),
		label,
		c.SerialNumber.String(),
		fingerprintString(crypto.MD5, c.Raw),
		fingerprintString(crypto.SHA1, c.Raw),
		fingerprintString(crypto.SHA256, c.Raw),
		p,
	}
	return parsed, nil
}
