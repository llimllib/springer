// TODO:
// * Board UI?
package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/llimllib/springer/client"
)

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
		pubkey, privkey = client.ValidKey()

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
