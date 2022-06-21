// TODO:
// * Board UI?
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

func validKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	// A conforming key's final seven hex characters must be 83e followed by
	// four characters that, interpreted as MMYY, express a valid month and
	// year in the range 01/00 .. 12/99. Formally, the key must match this
	//
	// regex: /83e(0[1-9]|1[0-2])(\d\d)$/
	//
	// Because we have an odd-length hex string, we don't encode the '8' here
	// and instead check it specifically in the hot loop... I'm open to ideas
	// about how to do this better. I'd like to keep everything in the hot loop
	// using the `bytes.Equal` function which is assembly on most platforms,
	// but we don't have a full byte for the `8`
	keyEnd := fmt.Sprintf("3e%s", time.Now().AddDate(2, 0, 0).Format("0106"))
	target, err := hex.DecodeString(keyEnd)
	if err != nil {
		panic(err)
	}

	nRoutines := runtime.NumCPU() - 1
	var waitGroup sync.WaitGroup
	var once sync.Once

	fmt.Printf(" - looking for a key that ends in 8%s using %d routines\n",
		keyEnd, nRoutines)

	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey
	start := time.Now()

	waitGroup.Add(nRoutines)
	for i := 0; i < nRoutines; i++ {
		go func() {
			for publicKey == nil {
				pub, priv, err := ed25519.GenerateKey(nil)
				if err != nil {
					panic(err)
				}

				// Here's where we check for the `8`; we do it after the
				// bytes.Equal to keep the hot loop fast
				if bytes.Equal(pub[29:32], target) && pub[28]&0x0F == 0x08 {
					once.Do(func() {
						fmt.Printf("found %x in %f minutes\n", pub, time.Since(start).Minutes())
						publicKey = pub
						privateKey = priv
					})
				}
			}
			waitGroup.Done()
		}()
	}

	waitGroup.Wait()

	return publicKey, privateKey
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func getKeys(folder string) (ed25519.PublicKey, ed25519.PrivateKey) {
	// get the expected public key file and private key file paths
	var pubfile, privfile string
	if len(folder) == 0 {
		user, err := user.Current()
		if err != nil {
			panic(err)
		}

		configPath := os.Getenv("XDG_CONFIG_HOME")
		if configPath == "" {
			configPath = filepath.Join(user.HomeDir, ".config", "spring83")
		}

		if err = os.MkdirAll(configPath, os.ModePerm); err != nil {
			panic(err)
		}

		pubfile = filepath.Join(configPath, "key.pub")
		privfile = filepath.Join(configPath, "key.priv")
	} else {
		pubfile = filepath.Join(folder, "key.pub")
		privfile = filepath.Join(folder, "key.priv")
	}

	// try to load the public and private key files as ed25519 keys
	var pubkey ed25519.PublicKey
	var privkey ed25519.PrivateKey
	var err error
	if fileExists(pubfile) && fileExists(privfile) {
		pubkey, err = ioutil.ReadFile(pubfile)
		if err != nil {
			panic(err)
		}

		privkey, err = ioutil.ReadFile(privfile)
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Generating valid key. This will take a minute")
		pubkey, privkey = validKey()

		os.WriteFile(pubfile, pubkey, 0666)
		os.WriteFile(privfile, privkey, 0600)
	}

	return pubkey, privkey
}

func getBody(inputFile string) []byte {
	var body []byte
	var err error
	if inputFile == "-" {
		body, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}
	} else {
		body, err = ioutil.ReadFile(inputFile)
		if err != nil {
			panic(err)
		}
	}

	// Prepend a time element. Maybe we should check to see if it's already
	// been provided?
	timeElt := []byte(fmt.Sprintf("<time datetime=\"%s\">", time.Now().UTC().Format(time.RFC3339)))
	body = append(timeElt, body...)

	if len(body) == 0 {
		panic(fmt.Errorf("input required"))
	}
	if len(body) > 2217 {
		panic(fmt.Errorf("input body too long"))
	}

	return body
}

func sendBody(server string, body []byte, pubkey ed25519.PublicKey, privkey ed25519.PrivateKey) {
	client := &http.Client{}

	url := fmt.Sprintf("%s/%x", server, pubkey)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	sig := ed25519.Sign(privkey, body)
	req.Header.Set("Authorization", fmt.Sprintf("Spring-83 Signature=%x", sig))

	dt := time.Now().Format(time.RFC1123)
	req.Header.Set("If-Unmodified-Since", dt)

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != 200 {
		fmt.Printf("%s: %s\n", resp.Status, responseBody)
	}
}

func usage() {
	fmt.Print(`springer [-file=filename] [-key=keyfolder] server

Send a spring83 board to a server

flags:
	-file=filename
		if present, a file to send to the server instead of accepting bytes on
		stdin
	-key=keyfolder
		a folder the program should use for finding your public and private
		keys. It will expect there to be two files, one called "key.pub" and
		another called "key.priv" which are your public and private keys,
		respectively
`)
	os.Exit(1)
}

func main() {
	inputFile := flag.String("file", "-", "The file to send to the server")
	keyFolder := flag.String("key", "", "A folder to check for key.pub and key.priv")
	flag.Usage = usage
	flag.Parse()

	if len(flag.Args()) < 1 {
		usage()
	}
	server := flag.Args()[0]

	pubkey, privkey := getKeys(*keyFolder)

	sendBody(server, getBody(*inputFile), pubkey, privkey)
}
