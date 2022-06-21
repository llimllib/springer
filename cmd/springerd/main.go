package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/llimllib/springer/server"
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

func main() {
	log := initLog()
	db := server.InitDB(log)
	server.InitRuntimeValues(log)
	server.InitCleaner(db, log)

	spring83 := server.NewSpring83Server(db, log)

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
		Handler:           server.RequestLogger(log, http.TimeoutHandler(spring83, 2*time.Second, timeoutMsg)),
	}

	log.Info().Str("addr", addr).Msg("starting helloserver on")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Err(err).Msg("Error received from server")
	}
}
