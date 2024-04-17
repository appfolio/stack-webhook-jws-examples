package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	port    = "8000"
	jwksURI = "https://api.appfolio.com/.well-known/jwks.json"
	header  = "X-JWS-Signature"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get(header)
		if signature == "" {
			log.Println("Missing", header, "header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		parts := strings.SplitN(signature, "..", 2)
		if len(parts) != 2 {
			log.Println("Invalid signature format")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		encodedHeader, encodedSignature := parts[0], parts[1]

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed to read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		encodedPayload := base64.RawURLEncoding.EncodeToString(body)

		message := fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, encodedSignature)

		set, err := jwk.Fetch(context.Background(), jwksURI)
		if err != nil {
			log.Printf("Failed to fetch JWKS: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Println("message", message)

		_, err = jws.Verify([]byte(message), jws.WithKeySet(set))

		if err != nil {
			log.Printf("Failed to verify signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		log.Println("Webhook received and signature verified")
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
