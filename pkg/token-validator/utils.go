package token_validator

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/eepurichandra/jwt-token-validator/pkg/models"
	"github.com/hpe-hcss/loglib/pkg/log"
	"gopkg.in/square/go-jose.v2"
)

func retrieveToken(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		errorStr := "[BAD REQUEST] : Authorization Token can't be empty"
		log.Error(ctx, errorStr)
		return "", fmt.Errorf(errorStr)
	}
	token := strings.TrimPrefix(accessToken, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	return token, nil
}

func decodeAccessToken(ctx context.Context, rawToken string) (models.Token, error) {
	_, err := jose.ParseSigned(rawToken)
	if err != nil {
		return models.Token{}, fmt.Errorf("oidc: malformed jwt: %v", err)
	}

	// Throw out tokens with invalid claims before trying to verify the token. This lets
	// us do cheap checks before possibly re-syncing keys.
	payload, err := parseJWT(rawToken)
	if err != nil {
		log.Errorf(ctx, "oidc: malformed jwt: %v", err)
		return models.Token{}, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	var token models.Token
	if err := json.Unmarshal(payload, &token); err != nil {
		log.Errorf(ctx, "oidc: failed to unmarshal claims: %v", err)
		return models.Token{}, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	}

	if token.UserID != "" {
		// Okta User token
		token.Subject = "users/" + token.UserID
	} else if token.ClientID != "" || token.KeycloakClientID != "" {
		token.Subject = "clients/" + token.Subject
	} else {
		// TODO This is just so that Keycloak tokens continue to work. Remove after keycloak is gone
		token.Subject = "users/" + token.Subject
	}

	return token, nil
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

func httpRequest(ctx context.Context, method, uri, contentType string, body io.Reader) (*http.Response, error) {
	transport := http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	urlParsed, err := url.Parse(uri)
	if err != nil {
		log.Errorf(ctx, "Failed to create a valid url with: (%s)", uri)
		return nil, err
	}

	log.Debugf(ctx, "Making %v req to %v", method, urlParsed.String())
	req, err := http.NewRequest(method, urlParsed.String(), body)
	if err != nil {
		log.Errorf(ctx, "Failed to create a valid request: %v", err)
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	response, err := transport.RoundTrip(req)
	if err != nil {
		log.Errorf(ctx, "Failed to get HTTP response. Error %v", err)
		return nil, err
	}

	if response.StatusCode > http.StatusAlreadyReported {
		apiResp, err := ioutil.ReadAll(response.Body)
		if err != nil {
			errMsg := fmt.Errorf("error occurred while reading response body. %v", err)
			log.Errorf(ctx, "%v", errMsg)
			return nil, errMsg
		}
		return nil, fmt.Errorf("failed HTTP Request - status code %v. Error: %v", response.StatusCode, string(apiResp))
	}

	return response, nil

}
