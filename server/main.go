// https://github.com/robinsloan/spring-83-spec/blob/main/draft-20220609.md
package main

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func initDB() *sql.DB {
	dbName := "./spring83.db"

	// if the db doesn't exist, create it
	if _, err := os.Stat(dbName); errors.Is(err, os.ErrNotExist) {
		log.Printf("initializing new database")
		db, err := sql.Open("sqlite3", dbName)
		must(err)

		initSQL := `
		CREATE TABLE boards (
			key text NOT NULL PRIMARY KEY,
			board text,
			expiry text
		);
		`

		_, err = db.Exec(initSQL)
		if err != nil {
			log.Fatal("%q: %s\n", err, initSQL)
		}
		return db
	}

	db, err := sql.Open("sqlite3", dbName)
	must(err)
	return db
}

func main() {
	db := initDB()
	log.Print("starting helloserver")

	server := newSpring83Server(db)
	http.HandleFunc("/", server.RootHandler)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

type Spring83Server struct {
	db *sql.DB
}

func newSpring83Server(db *sql.DB) *Spring83Server {
	return &Spring83Server{
		db: db,
	}
}

func (s *Spring83Server) publishBoard(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if len(body) > 2217 {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	var mtime time.Time
	if ifUnmodifiedHeader, ok := r.Header["If-Unmodified-Since"]; !ok {
		http.Error(w, "Missing If-Unmodified-Since header", http.StatusBadRequest)
		return
	} else {
		// spec says "in HTTP format", but it's not entirely clear if this matches?
		if mtime, err = time.Parse(time.RFC1123, ifUnmodifiedHeader[0]); err != nil {
			http.Error(w, "Invalid format for If-Unmodified-Since header", http.StatusBadRequest)
			return
		}
	}

	// TODO : If this value (mtime) is older or equal to the timestamp of the
	// server's version of the board, the server must reject the request with
	// 409 Conflict.
	//
	// this is just here to allow the variable to exist
	log.Printf("%s\n", mtime)

	var signature []byte
	if authorizationHeaders, ok := r.Header["Authorization"]; !ok {
		http.Error(w, "Missing Authorization header", http.StatusBadRequest)
		return
	} else {
		parts := strings.Split(authorizationHeaders[0], " ")
		if parts[0] != "Spring-83" || len(parts) < 2 {
			http.Error(w, "Invalid Authorization Type", http.StatusBadRequest)
			return
		}

		sig := strings.Split(parts[1], "=")
		if len(sig) < 1 {
			http.Error(w, "Invalid Signature", http.StatusBadRequest)
			return
		}

		sigString := sig[1]
		if len(sigString) != 128 {
			http.Error(w, fmt.Sprintf("Expecting 64-bit signature %s %d", sigString, len(sigString)), http.StatusBadRequest)
			return
		}

		signature, err = hex.DecodeString(sigString)
		if err != nil {
			http.Error(w, "Unable to decode signature", http.StatusBadRequest)
			return
		}
	}

	// Spring '83 specifies a test keypair
	// Servers must not accept PUTs for this key, returning 401 Unauthorized.
	// The server may also use a denylist to block certain keys, rejecting all PUTs for those keys.
	denylist := []string{"fad415fbaa0339c4fd372d8287e50f67905321ccfd9c43fa4c20ac40afed1983"}
	for _, key := range denylist {
		if bytes.Compare(signature, []byte(key)) == 0 {
			http.Error(w, "Denied", http.StatusUnauthorized)
		}
	}

	// the path must be a ed25519 public key of 32 bytes
	fmt.Printf("%s\n", r.URL.Path[1:])
	key, err := hex.DecodeString(r.URL.Path[1:])
	if err != nil || len(key) != 32 {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	// If the current four-digit year is YYYY, and the
	// previous four-digit year is YYYX, the server must
	// only accept PUTs for keys that end with the four
	// digits YYYY or YYYX, preceded in turn by the two hex
	// digits "ed". This is the years-of-use requirement.
	//
	// The server must reject other keys with 400 Bad
	// Request.
	keyStr := fmt.Sprintf("%x", key)
	last4 := string(keyStr[60:64])
	if keyStr[58:60] != "ed" ||
		(last4 != time.Now().Format("2006") &&
			last4 != time.Now().AddDate(1, 0, 0).Format("2006")) {
		log.Printf("%s %s %s", keyStr[58:60] == "ed", last4 == time.Now().Format("2006"), time.Now().Format("2006"))
		http.Error(w, "Signature must end with edYYYY", http.StatusBadRequest)
		return
	}

	// at this point, we should have met all the preconditions prior to the
	// cryptographic check. By the spec, we should perform all
	// non-cryptographic checks first.
	if !ed25519.Verify(key, body, signature) {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	// TODO:
	// 	Additionally, if the server doesn't have any board
	// 	stored for <key>, then it must apply another check. The
	// 	key, interpreted as a 256-bit number, must be less than
	// 	a threshold defined by the server's difficulty factor:
	//
	// MAX_SIG = (2**256 - 1) key_threshold = MAX_SIG * ( 1.0 -
	//            difficulty_factor)
	//
	// This check is not applied to keys for which the server
	// already has a board stored. You can read more about the
	// difficulty factor later in this document.

	expiry := time.Now().AddDate(0, 0, 7).Format(time.RFC3339)
	_, err = s.db.Exec(`
		INSERT INTO boards (key, board, expiry)
		            values(?, ?, ?)
	    ON CONFLICT(key) DO UPDATE SET
			board=?,
			expiry=?
	`, keyStr, body, expiry, body, expiry)

	if err != nil {
		log.Printf("%s", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
}

func (s *Spring83Server) showBoard(w http.ResponseWriter, r *http.Request) {
}

func (s *Spring83Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		s.publishBoard(w, r)
	} else if r.Method == "GET" {
		s.showBoard(w, r)
	} else {
		http.Error(w, "Invalid method", http.StatusBadRequest)
	}
}
