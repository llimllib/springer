package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

func validKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// TODO: generate a new key if necessary
	target, err := hex.DecodeString("ed2023")
	if err != nil {
		panic(err)
	}

	for bytes.Compare(pub[29:32], target) != 0 {
		// fmt.Printf("%x\n", pub[29:32])
		pub, priv, err = ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("%s\n", fmt.Sprintf("%x", pub))
	return pub, priv
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func getKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
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

	pubfile := filepath.Join(configPath, "key.pub")
	privfile := filepath.Join(configPath, "key.priv")
	var pubkey ed25519.PublicKey
	var privkey ed25519.PrivateKey
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
		fmt.Printf("Generating key, give this a minute or two\n")
		pubkey, privkey = validKey()

		os.WriteFile(pubfile, pubkey, 0666)
		os.WriteFile(privfile, privkey, 0600)
	}

	return pubkey, privkey
}

func main() {
	pubkey, privkey := getKeys()

	// initialize http client
	client := &http.Client{}

	body, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	if len(body) == 0 {
		panic(fmt.Errorf("input required"))
	}
	if len(body) > 2217 {
		panic(fmt.Errorf("input body too long"))
	}

	// set the HTTP method, url, and request body
	url := fmt.Sprintf("http://localhost:8000/%x", pubkey)
	fmt.Printf("URL: %s\n", url)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	sig := ed25519.Sign(privkey, body)
	fmt.Printf("Spring-83 Signature=%x\n", sig)
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

	fmt.Printf("%s: %s\n", resp.Status, responseBody)
}
