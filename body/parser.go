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

package body

import (
	"encoding/json"
	"errors"
	"github.com/Lukasa/mkcert/certs"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
)

var (
	MissingFormName error = errors.New("Missing form name.")
	InvalidJSONPart error = errors.New("Invalid JSON part.")
)

// ParseMultipartBody takes a single HTTP request body that has been identified as being
// multipart and parses it according to what mkcert expects. In this case, the expectation
// is that there will be at least one part that contains a JSON-serialized list of labels,
// as with the normal upload, as well as zero-or-more PEM files, each containing one-or-more
// x509 certificates.
//
// This function returns the slice of labels in the first element, the slice of parsed PEM
// certificates in the second, and an error in the third. If an error is encountered no
// data is read.
func ParseMultipartBody(f io.Reader, boundary string) ([]string, []*certs.Certificate, error) {
	mr := multipart.NewReader(f, boundary)
	certificates := make([]*certs.Certificate, 0)
	var labels []string

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error parsing multipart body: %v.\n", err)
			return nil, nil, err
		}

		formName := p.FormName()
		if formName == "" {
			log.Println("No form name present.")
			return nil, nil, MissingFormName
		}

		if formName == "filter" {
			// This is the JSON filter portion of the request. Decode it as a list of
			// strings.
			decoder := json.NewDecoder(p)
			err = decoder.Decode(&labels)
			if err != nil && err != io.EOF {
				log.Println("Invalid JSON part.")
				return nil, nil, InvalidJSONPart
			}
		} else {
			// This is a PEM certificate. Decode it, and grab the label.
			labelVals, ok := p.Header["Label"]
			var label string
			if !ok {
				label = ""
			} else {
				label = labelVals[0]
			}

			body, err := ioutil.ReadAll(p)
			if err != nil {
				log.Printf("Unexpected IO error: %v.\n", err)
				return nil, nil, err
			}

			parsed, err := certs.DecodePEMBlock(body, label)
			if err != nil {
				log.Printf("Unexpected decoder error: %v", err)
				return nil, nil, err
			}

			certificates = append(certificates, parsed...)
		}
	}

	return labels, certificates, nil
}
