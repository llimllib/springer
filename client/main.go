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
	// using the `bytes.compare` function which is assembly on most platforms,
	// but we don't have a full byte for the `8`
	keyEnd := fmt.Sprintf("3e%s", time.Now().AddDate(2, 0, 0).Format("0106"))
	target, err := hex.DecodeString(keyEnd)
	if err != nil {
		panic(err)
	}

	nRoutines := runtime.NumCPU() - 1
	var waitGroup sync.WaitGroup
	var once sync.Once

	fmt.Printf(" - looking for a key that ends in %s using %d routines\n",
		keyEnd, nRoutines)

	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey

	waitGroup.Add(nRoutines)
	for i := 0; i < nRoutines; i++ {
		go func(num int) {
			for publicKey == nil {
				pub, priv, err := ed25519.GenerateKey(nil)
				if err != nil {
					panic(err)
				}

				// Here's where we check for the `8`; we do it after the
				// bytes.Compare to keep the hot loop fast
				if bytes.Compare(pub[29:32], target) == 0 && pub[28]&0x0F == 0x08 {
					once.Do(func() {
						fmt.Printf("found %x\n", pub)
						publicKey = pub
						privateKey = priv
					})
				}
			}
			waitGroup.Done()
		}(i)
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
		fmt.Printf("I am fishing in the sea of all possible keys for a valid spring83 key. This may take a bit...\n")
		pubkey, privkey = validKey()

		os.WriteFile(pubfile, pubkey, 0666)
		os.WriteFile(privfile, privkey, 0600)
	}

	return pubkey, privkey
}

func main() {
	pubkey, privkey := getKeys()

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

	// TODO: take the URL as a command line param
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
