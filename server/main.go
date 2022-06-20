// https://github.com/robinsloan/spring-83-spec/blob/main/draft-20220616.md
// TODO:
//  * check that the <time> tag in the body
//  * implement peer sharing and receiving
//  * display each board in a region with an aspect ratio of either 1:sqrt(2) or sqrt(2):1
//  * add <link> elements:
//     * However, it is presumed that a home page or profile page might contain a <link> element analogous to the kind used to specify RSS feeds. A client scanning a web page for an associated board should look for <link> elements with the type attribute set to text/board+html.
//		 <link rel="alternate" type="text/board+html" href="https://bogbody.biz/ca93846ae61903a862d44727c16fed4b80c0522cab5e5b8b54763068b83e0623" />
//  * scan for <link rel="next"...> links as specified in the spec
//  * add unique request ID

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"text/template"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const MAX_KEY_64 = (1 << 64) - 1
const MAX_BODY_SIZE = 2217

var (
	// For the convenience of server implementers, the <time> element must fit
	// the following format exactly; "valid HTML" is not sufficient:
	// <time datetime="YYYY-MM-DDTHH:MM:SSZ">
	TIME_RE = regexp.MustCompile("<time datetime=\".{19}Z\">")

	//go:embed templates/*
	templateFS embed.FS

	// information about the process, for logging
	process   = os.Args[0]
	pid       = syscall.Getpid()
	goversion = runtime.Version()

	// set by initRuntimeValues
	vcsRevision string
	vcsTime     string
)

// getenv returns the environment variable given by the key if present,
// otherwise it returns adefault
func getenv(key string, adefault string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return adefault
	}
	return val
}

func must(err error, log zerolog.Logger) {
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
}

func initDB(log zerolog.Logger) *sql.DB {
	dbName := "./spring83.db"

	// if the db doesn't exist, create it
	if _, err := os.Stat(dbName); errors.Is(err, os.ErrNotExist) {
		log.Info().Msg("initializing new database")
		db, err := sql.Open("sqlite3", dbName)
		must(err, log)

		initSQL := `
		CREATE TABLE boards (
			key text NOT NULL PRIMARY KEY,
			board text,
			creation_datetime text,
			expiry_datetime text
		);
		`

		_, err = db.Exec(initSQL)
		if err != nil {
			log.Fatal().Msgf("%q: %s\n", err, initSQL)
		}
		return db
	}

	db, err := sql.Open("sqlite3", dbName)
	must(err, log)
	return db
}

func initLog() zerolog.Logger {
	logLevel := getenv("LOG_LEVEL", "info")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Panic().Err(err).Msg("")
	}

	log := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(level)
	if getenv("PRETTY_LOGGING", "") != "" {
		log = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}

	return log
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *responseRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func requestLogger(log zerolog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{w, http.StatusOK}
		t := time.Now()
		next.ServeHTTP(rec, r)
		log.Info().
			Dur("duration", time.Since(t)).
			Int("status", rec.status).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("process", process).
			Int("pid", pid).
			Str("goversion", goversion).
			Str("peer-ip", r.RemoteAddr).
			Str("difficulty", w.Header().Get("Spring-Difficulty")).
			Str("vcsRevision", vcsRevision).
			Str("vcsTime", vcsTime).
			Msg("Request served")
	})
}

func initRuntimeValues(log zerolog.Logger) {
	if bi, ok := debug.ReadBuildInfo(); !ok {
		log.Fatal().Msg("Unable to get build info")
	} else {
		for i := range bi.Settings {
			switch bi.Settings[i].Key {
			case "vcs.revision":
				vcsRevision = bi.Settings[i].Value
			case "vcs.time":
				vcsTime = bi.Settings[i].Value
			}
		}
	}
}

func removeExpiredBoards(db *sql.DB, log zerolog.Logger) {
	t := time.Now()
	dt := t.Format(time.RFC3339)

	// This should work because ISO datetimes are lexicographically ordered
	res, err := db.Exec(`
		DELETE FROM boards
		WHERE expiry_datetime < ?
	`, dt)
	if err != nil {
		log.Error().Err(err).Msg("Error inserting board")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		log.Error().Err(err).Msg("Error inserting board")
	}

	log.Info().Int64("deleted", rows).Dur("duration", time.Since(t)).Msg("entries cleaned")
}

// initCleaner starts a goroutine that will delete any expired entries every 5 minutes
func initCleaner(db *sql.DB, log zerolog.Logger) {
	removeExpiredBoards(db, log)
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for {
			<-ticker.C
			removeExpiredBoards(db, log)
		}
	}()
}

func main() {
	log := initLog()
	db := initDB(log)
	initRuntimeValues(log)
	initCleaner(db, log)

	server := newSpring83Server(db, log)

	host := getenv("HOST", "")
	port := getenv("PORT", "8000")
	addr := fmt.Sprintf("%s:%s", host, port)
	timeoutMsg := "Request timed out"

	srv := &http.Server{
		Addr:              addr,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           requestLogger(log, http.TimeoutHandler(server, 2*time.Second, timeoutMsg)),
	}

	log.Info().Str("addr", addr).Msg("starting helloserver on")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Err(err).Msg("Error received from server")
	}
}

func readTemplate(name string, fsys fs.FS) (string, error) {
	h, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func mustTemplate(name string, fsys fs.FS) *template.Template {
	f, err := readTemplate(name, fsys)
	if err != nil {
		panic(err)
	}

	t, err := template.New("index").Parse(f)
	if err != nil {
		panic(err)
	}

	return t
}

type Board struct {
	Key      string
	Board    string
	Creation time.Time
	Expiry   time.Time
}

type Spring83Server struct {
	db           *sql.DB
	log          zerolog.Logger
	homeTemplate *template.Template
}

func newSpring83Server(db *sql.DB, log zerolog.Logger) *Spring83Server {
	return &Spring83Server{
		db:           db,
		log:          log,
		homeTemplate: mustTemplate("templates/index.html", templateFS),
	}
}

func (s *Spring83Server) getBoard(key string) (*Board, error) {
	query := `
		SELECT key, board, creation_datetime, expiry_datetime
		FROM boards
		WHERE key=?
	`
	row := s.db.QueryRow(query, key)

	var dbkey, board, creation, expiry string
	err := row.Scan(&dbkey, &board, &creation, &expiry)
	if err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
		return nil, nil
	}

	creationTime, err := time.Parse(time.RFC3339, creation)
	if err != nil {
		return nil, err
	}

	expTime, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		return nil, err
	}

	return &Board{
		Key:      key,
		Board:    board,
		Creation: creationTime,
		Expiry:   expTime,
	}, nil
}

func (s *Spring83Server) boardCount() (int, error) {
	query := `
		SELECT count(*)
		FROM boards
	`
	row := s.db.QueryRow(query)

	var count int
	err := row.Scan(&count)
	if err != nil {
		if err != sql.ErrNoRows {
			return 0, err
		}
		panic(err)
	}

	return count, nil
}

func (s *Spring83Server) getDifficulty() (float64, uint64, error) {
	count, err := s.boardCount()
	if err != nil {
		return 0, 0, err
	}

	//	The calculation of the difficulty factor is not part of this specification, but here's an example formula that works well:
	//
	//   difficulty_factor = ( num_boards_stored / max_boards )**4
	//
	// a threshold defined by the server's difficulty factor:
	//
	//    MAX_KEY_64 = (2**64 - 1)
	//    key_64_threshold = round(MAX_KEY_64 * ( 1.0 - difficulty_factor))
	difficultyFactor := math.Pow(float64(count)/10_000_000, 4)
	keyThreshold := uint64(math.Round(MAX_KEY_64 * (1.0 - difficultyFactor)))
	return difficultyFactor, keyThreshold, nil
}

func (s *Spring83Server) publishBoard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Spring-Version", "83")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if len(body) > MAX_BODY_SIZE {
		http.Error(w, "Payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	key, err := hex.DecodeString(r.URL.Path[1:])
	if err != nil || len(key) != 32 {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}
	keyStr := fmt.Sprintf("%x", key)

	// curBoard is nil if there is no existing board for this key, and a Board object otherwise
	curBoard, err := s.getBoard(keyStr)
	if err != nil {
		s.log.Err(err).Msg("Unable to get board")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// if the server doesn't have any board stored for <key>, then it must
	// apply another check. The key, interpreted as a 256-bit number, must be
	// less than a threshold defined by the server's difficulty factor:
	if curBoard == nil {
		difficultyFactor, keyThreshold, err := s.getDifficulty()
		if err != nil {
			s.log.Err(err).Msg("Unable to get difficulty")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		s.log.Info().Float64("diff", difficultyFactor).Msg("difficulty")
		w.Header().Add("Spring-Difficulty", fmt.Sprintf("%f", difficultyFactor))

		// If the server doesn't yet have any board stored for the key, then it
		// must apply an additional check. The key's first 16 hex characters,
		// interpreted as a 64-bit number, must be less than a threshold
		// defined by the server's difficulty factor:
		//
		//    MAX_KEY_64 = (2**64 - 1)
		//    key_64_threshold = round(MAX_KEY_64 * ( 1.0 - difficulty_factor))
		//
		// If the key fails this check, the server must reject the PUT request, returning 403 Forbidden.
		if binary.BigEndian.Uint64(key[:8]) < keyThreshold {
			if err != nil || len(key) != 32 {
				http.Error(w, "Key greater than threshold", http.StatusForbidden)
				return
			}
		}
	}

	// Verify that the provided signature matches the body content
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
		if bytes.Equal(signature, []byte(key)) {
			http.Error(w, "Denied", http.StatusUnauthorized)
		}
	}

	// A conforming key's final seven hex characters must be "83e" followed by
	// four characters that, interpreted as MMYY, express a valid month and
	// year in the range 01/00 .. 12/99. Formally, the key must match this
	// regex:
	// /83e(0[1-9]|1[0-2])(\d\d)$/
	//
	// If the key does not match that regex, the server must reject the
	// request, returning 403 Forbidden.
	//
	// The key is only valid in the two years preceding its encoded expiration
	// date, and expires at the end of the last day of the month specified. For
	// example, the key
	last4 := string(keyStr[60:64])
	last4Time, err := time.Parse("0106", last4)
	if err != nil {
		s.log.Error().Str("last4", last4).Msg("Failed parsing last4")
		http.Error(w, "Key must end with 83eMMYY", http.StatusBadRequest)
		return
	}

	// This isn't quite the correct key expiry date; techncially the key
	// expires on the last day of the month of its issuance; here we're just
	// giving it an extra month. TODO be more accurate
	twoYearsInHours := (365 * 2 * 24.0) + 31*24.0
	timeDiff := time.Until(last4Time).Hours()
	if keyStr[57:60] != "83e" {
		s.log.Error().Str("keyStr", keyStr[57:60]).Msg("Expected 83e")
		http.Error(w, "Key must end with 83eMMYY", http.StatusBadRequest)
		return
	}
	if timeDiff > twoYearsInHours {
		s.log.Error().Float64("timeDiff", timeDiff).Msg("Key too far in future")
		http.Error(w, "Key is not yet valid", http.StatusBadRequest)
		return
	}
	if timeDiff < 0 {
		s.log.Error().Float64("timeDiff", timeDiff).Msg("Key expired")
		http.Error(w, "Key is expired", http.StatusBadRequest)
		return
	}

	// at this point, we should have met all the preconditions prior to the
	// cryptographic check. By the spec, we should perform all
	// non-cryptographic checks first.
	if !ed25519.Verify(key, body, signature) {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	// The server must reject the PUT request, returning 400 Bad Request, if
	//
	// - the request is transmitted without a <time> element; or
	// - its <time> element's datetime attribute is not a UTC timestamp in ISO
	//   8601 format; or
	// - its <time> element's datetime attribute is set to a timestamp in the
	//   future.
	match := TIME_RE.Find(body)
	if match == nil {
		s.log.Error().Bytes("body", body).Msg("No time element in body")
		http.Error(w, "Missing time element in body", http.StatusBadRequest)
		return
	}
	if len(match) != 38 {
		s.log.Error().Bytes("match", match).Int("len", len(match)).Msg("invalid match length")
		http.Error(w, "Invalid time element in body", http.StatusBadRequest)
		return
	}
	bodyTime, err := time.Parse(time.RFC3339, string(match[16:36]))
	if err != nil {
		s.log.Error().Bytes("matchtime", match[16:36]).Msg("Unable to parse")
		http.Error(w, "Invalid time element in body", http.StatusBadRequest)
		return
	}
	if time.Now().Before(bodyTime) {
		s.log.Error().Time("bodyTime", bodyTime).Msg("Future time")
		http.Error(w, "Future times are not allowed", http.StatusBadRequest)
		return
	}

	if curBoard != nil && bodyTime.Before(curBoard.Creation) {
		s.log.Error().Time("bodyTime", bodyTime).Msg("Old content")
		http.Error(w, "Old content", http.StatusConflict)
		return
	}

	expiry := time.Now().AddDate(0, 0, 7).Format(time.RFC3339)
	bodyTimeISO := bodyTime.Format(time.RFC3339)
	_, err = s.db.Exec(`
		INSERT INTO boards (key, board, creation_datetime, expiry_datetime)
		            values(?, ?, ?, ?)
	    ON CONFLICT(key) DO UPDATE SET
			board=?,
			creation_datetime=?,
			expiry_datetime=?
	`, keyStr, body, bodyTimeISO, expiry, body, bodyTimeISO, expiry)

	if err != nil {
		s.log.Error().Err(err).Msg("Error inserting board")
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
}

func (s *Spring83Server) loadBoards() ([]Board, error) {
	query := `
		SELECT key, board, creation_datetime, expiry_datetime
		FROM boards
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}

	boards := []Board{}
	for rows.Next() {
		var key, board, creation, expiry string

		err = rows.Scan(&key, &board, &creation, &expiry)
		if err != nil {
			return nil, err
		}

		creationTime, err := time.Parse(time.RFC3339, creation)
		if err != nil {
			return nil, err
		}

		expTime, err := time.Parse(time.RFC3339, expiry)
		if err != nil {
			return nil, err
		}

		boards = append(boards, Board{
			Key:      key,
			Board:    board,
			Creation: creationTime,
			Expiry:   expTime,
		})
	}

	return boards, nil
}

func randstr() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("failed to read random bytes to create random string")
	}

	// format it in hexadecimal, and start it with an n because html can have
	// problems with strings starting with 0 and we're using it as a nonce
	return fmt.Sprintf("n%x", buf)
}

// for now, on loads to /, I'm just going to show all boards no matter what
func (s *Spring83Server) showAllBoards(w http.ResponseWriter, r *http.Request) {
	boards, err := s.loadBoards()
	if err != nil {
		s.log.Err(err).Msg("Unable to load boards")
		http.Error(w, "Unable to load boards", http.StatusInternalServerError)
		return
	}

	difficultyFactor, _, err := s.getDifficulty()
	if err != nil {
		s.log.Err(err).Msg("Unable to get difficulty")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Spring-Difficulty", fmt.Sprintf("%f", difficultyFactor))

	nonce := randstr()
	policy := []string{
		"default-src: 'none'",
		"style-src: 'self' 'unsafe-inline'",
		"font-src 'self'",
		fmt.Sprintf("script-src 'nonce-%s'", nonce),
		"form-action *",
		"connect-src *",
		"img-src self",
	}

	w.Header().Add("Content-Security-Policy", strings.Join(policy, "; "))

	boardBytes, err := json.Marshal(boards)
	if err != nil {
		s.log.Err(err).Msg("Unable to marshal boards")
		http.Error(w, "Unable to marshal boards", http.StatusInternalServerError)
		return
	}

	data := struct {
		Boards string
		Nonce  string
	}{
		Boards: string(boardBytes),
		Nonce:  nonce,
	}

	s.homeTemplate.Execute(w, data)
}

func (s *Spring83Server) showBoard(w http.ResponseWriter, r *http.Request) {
	board, err := s.getBoard(r.URL.Path[1:])
	if err != nil {
		s.log.Err(err).Str("path: ", r.URL.Path).Msg("Unable to get board")
		http.Error(w, "Unable to load boards", http.StatusInternalServerError)
		return
	}
	if board == nil {
		http.Error(
			w,
			fmt.Sprintf("Could not find board %s", r.URL.Path[1:]),
			http.StatusNotFound)
		return
	}

	difficultyFactor, _, err := s.getDifficulty()
	if err != nil {
		s.log.Err(err).Msg("Unable to get difficulty")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Spring-Difficulty", fmt.Sprintf("%f", difficultyFactor))

	// XXX: we want to block all javascript from executing, except for our own
	// script, with a CSP but I'm not sure exactly how to do that. This does
	// seem to block a simple onclick handler I added to the code, which is
	// nice
	nonce := randstr()
	w.Header().Add("Content-Security-Policy", fmt.Sprintf("script-src 'nonce-%s'; img-src 'self'", nonce))

	boardBytes, err := json.Marshal([]*Board{board})
	if err != nil {
		s.log.Err(err).Msg("Unable to marshal board")
		http.Error(w, "Unable to marshal boards", http.StatusInternalServerError)
		return
	}

	data := struct {
		Boards string
		Nonce  string
	}{
		Boards: string(boardBytes),
		Nonce:  nonce,
	}

	// for now just be lazy and don't give this page its own template, re-use
	// the page designed to show all boards
	s.homeTemplate.Execute(w, data)
}

func (s *Spring83Server) Options(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type, If-Modified-Since, Spring-Signature, Spring-Version")
	w.Header().Add("Access-Control-Expose-Headers", "Content-Type, Last-Modified, Spring-Difficulty, Spring-Signature, Spring-Version")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Spring83Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "OPTIONS":
		s.Options(w, r)
	case "PUT":
		s.publishBoard(w, r)
	case "GET":
		if len(r.URL.Path) == 1 {
			s.showAllBoards(w, r)
		} else {
			s.showBoard(w, r)
		}
	default:
		http.Error(w, "Invalid method", http.StatusBadRequest)
	}
}
