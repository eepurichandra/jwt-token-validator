package token_validator

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/hpe-hcss/loglib/pkg/log"

	"github.com/eepurichandra/jwt-token-validator/pkg/constants"
)

func ValidateToken(ctx context.Context, accessToken string) error {
	_, err := retrieveToken(ctx, accessToken)
	if err != nil {
		return err
	}

	decodedToken, err := decodeAccessToken(ctx, accessToken)
	if err != nil {
		return err
	}

	err = validateJWT(ctx, accessToken, decodedToken.Issuer, decodedToken.TenantID)
	if err != nil {
		return err
	}

	return nil
}

func getPublicKeys(ctx context.Context, issuer string) (map[string]*rsa.PublicKey, error) {
	rsakeys := make(map[string]*rsa.PublicKey)
	var body map[string]interface{}
	uri := issuer + constants.OktaPublicKeyApiPath
	resp, err := httpRequest(ctx, http.MethodGet, uri, constants.ContentTypeJson, nil)
	if err != nil {
		return nil, err
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		log.Errorf(ctx, "Failed to decode request body : %v", err)
		return nil, err
	}

	for _, bodykey := range body["keys"].([]interface{}) {
		key := bodykey.(map[string]interface{})
		kid := key["kid"].(string)
		rsakey := new(rsa.PublicKey)
		number, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
		rsakey.N = new(big.Int).SetBytes(number)
		rsakey.E = 65537
		rsakeys[kid] = rsakey
	}
	return rsakeys, nil
}

func validateJWT(ctx context.Context, jwtToken, issuer, tenantID string) error {
	rsaKeys, err := getPublicKeys(ctx, issuer)
	if err != nil {
		log.Errorf(ctx, "Failed to getting the public keys from issuer: %v", err)
		return err
	}

	isValid := false
	errorMessage := ""
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return rsaKeys[token.Header["kid"].(string)], nil
	})

	if err != nil {
		log.Errorf(ctx, "got error while parsing token. Error: %v", err)
		errorMessage = err.Error()
	} else if !token.Valid {
		errorMessage = "Invalid token"
	} else if token.Header["alg"] == nil {
		errorMessage = "alg must be defined"
	} else if token.Claims.(jwt.MapClaims)["aud"] != "api://default" { // "api://api.greenlake.hpe.com" {
		errorMessage = "Invalid aud"
	} else if !strings.Contains(token.Claims.(jwt.MapClaims)["iss"].(string), tenantID) {
		errorMessage = "Invalid iss"
	} else {
		isValid = true
	}
	if !isValid {
		err = fmt.Errorf("%v. %v", errorMessage, err)
		return err
	}
	return nil
}
