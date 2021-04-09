package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/go-chi/chi"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	r := chi.NewRouter()
	r.Post("/", handler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8023"
	}

	err := http.ListenAndServe(":"+port, r)
	if errors.Is(err, http.ErrServerClosed) {
		return
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	rawCredentials := r.FormValue("credentials")
	scopes := strings.Split(r.FormValue("scopes"), ",")
	if rawCredentials == "" || len(scopes) == 0 || scopes[0] == "" {
		http.Error(w, "expected credentials and scopes", http.StatusBadRequest)
		return
	}

	var credentials json.RawMessage
	err := json.Unmarshal([]byte(rawCredentials), &credentials)
	if err != nil {
		http.Error(w, "invalid credentials, expected JSON object", http.StatusBadRequest)
		return
	}

	src, err := getTokenSource(credentials, scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := src.Token()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(token)
}

var tokenSources = struct {
	sync.Mutex
	m map[string]oauth2.TokenSource
}{
	m: map[string]oauth2.TokenSource{},
}

func getTokenSource(credentials json.RawMessage, scopes []string) (oauth2.TokenSource, error) {
	tokenSources.Lock()
	defer tokenSources.Unlock()

	key, _ := json.Marshal([]interface{}{credentials, scopes})

	src, ok := tokenSources.m[string(key)]
	if ok {
		return src, nil
	}

	var obj struct {
		ImpersonateUser string `json:"impersonate_user"`
	}
	_ = json.Unmarshal(credentials, &obj)
	cfg, err := google.JWTConfigFromJSON(credentials, scopes...)
	if err != nil {
		return nil, err
	}
	cfg.Subject = obj.ImpersonateUser

	src = cfg.TokenSource(context.Background())
	tokenSources.m[string(key)] = src
	return src, nil
}
