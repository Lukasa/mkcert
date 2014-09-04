package main

import (
	"github.com/Lukasa/trustdeck/certs"
	"log"
	"os"
	"runtime"
)

func main() {
	// Before we do anything, TURN ON THE CPUS.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// As an initial basic test that the logic works, let's parse a file.
	infile, err := os.Open("certdata.txt")
	if err != nil {
		log.Fatalf("Failed to open input file: %s", err)
	}

	_, _, objects := certs.ParseInput(infile)
	infile.Close()

	certs.OutputTrustedCerts(os.Stdout, objects)
}
