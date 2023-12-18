package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	nc "github.com/vpngen/vpngine/naclkey"
	"golang.org/x/crypto/nacl/box"
)

func printDefaults() {
	fmt.Fprintln(os.Stderr, `Usage: nacl [<flags>] <cmd> [<args>]
	Available subcommands:
	  genkey           Generates a new private key and writes it to stdout
	  pubkey           Reads a private key from stdin and writes a public key to stdout
	  seal pub.json    Reads data from stdin, encrypts it into a sealed box, writes the box to stdout
	  unseal priv.json Reads a sealed box from stdin, decrypts it, writes data to stdout`)
	flag.PrintDefaults()
}

func main() {

	b64recoding := flag.Bool("b", false, "Automatically base64 decoding input and encoding output while seal/unseal")

	flag.Parse()

	switch len(flag.Args()) {
	case 1:
		switch flag.Arg(0) {
		case "genkey":
			publicKey, privateKey, err := box.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatalf("failed to genrate key: %s\n", err)
			}

			blob, err := nc.MarshalKeypair(
				nc.NaclBoxKeypair{
					Public:  *publicKey,
					Private: *privateKey,
				},
			)
			if err != nil {
				log.Fatalf("failed to format JSON: %s\n", err)
			}

			fmt.Println(string(blob))

		case "pubkey":
			blob, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatalf("failed to read key from stdin: %s\n", err)
			}

			in, err := nc.UnmarshalKeypair(blob)
			if err != nil {
				log.Fatalf("failed to read JSON key: %s\n", err)
			}

			blob, err = nc.MarshalPublicKey(in.Public)
			if err != nil {
				log.Fatalf("failed to format JSON: %s\n", err)
			}

			fmt.Println(string(blob))
		}
	case 2:
		var (
			r io.Reader
			w io.WriteCloser
		)

		switch *b64recoding {
		case true:
			r = base64.NewDecoder(base64.StdEncoding, os.Stdin)
			w = base64.NewEncoder(base64.StdEncoding, os.Stdout)

			defer w.Close()
		default:
			r = os.Stdin
			w = os.Stdout
		}

		keyfilename := flag.Arg(1)

		switch flag.Arg(0) {
		case "seal":
			pubkey, err := nc.ReadPublicKeyFile(keyfilename)
			if err != nil {
				log.Fatalf("failed to read key: %s\n", err)
			}

			blob, err := io.ReadAll(r)
			if err != nil {
				log.Fatalf("failed to read message from stdin: %s\n", err)
			}

			out, err := box.SealAnonymous(nil, blob, &pubkey, rand.Reader)
			if err != nil {
				log.Fatalf("failed to seal the box: %s\n", err)
			}

			_, err = w.Write(out)
			if err != nil {
				log.Fatalf("failed to write the box: %s\n", err)
			}
		case "unseal":
			keys, err := nc.ReadKeypairFile(keyfilename)
			if err != nil {
				log.Fatalf("failed to read key from %s: %s\n", keyfilename, err)
			}

			blob, err := io.ReadAll(r)
			if err != nil {
				log.Fatalf("failed to read the box from stdin: %s\n", err)
			}

			out, ok := box.OpenAnonymous(nil, blob, &keys.Public, &keys.Private)
			if !ok {
				log.Fatalf("failed to open the box\n")
			}

			_, err = w.Write(out)
			if err != nil {
				log.Fatalf("failed to write the message: %s\n", err)
			}
		}
	case 0:
		printDefaults()
	default:
		printDefaults()
		log.Fatalf("Unknown args: %v\n", flag.Args())
	}
}
