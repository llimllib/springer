package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"time"
)

func ValidKey() (ed25519.PublicKey, ed25519.PrivateKey) {
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
