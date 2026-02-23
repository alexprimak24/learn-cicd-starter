package auth

import (
	"errors"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")
var ErrMalformedAuthHeader = errors.New("malformed authorization header")

type HeaderGetter interface {
	Get(key string) string
}

// GetAPIKey -
func GetAPIKey(headers HeaderGetter) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", ErrMalformedAuthHeader
	}

	return splitAuth[1], nil
}
