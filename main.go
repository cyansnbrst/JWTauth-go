package main

import (
	"log"
	"net/http"
)

func main() {
	// Эндпоинты
	http.HandleFunc("/login", getTokenPair)
	http.HandleFunc("/refresh", refresh)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
