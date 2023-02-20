package models

// Token a jwt token format
type Token struct {
	Issuer           string `json:"iss"`
	Subject          string `json:"sub"`
	Expiry           int64  `json:"exp"`
	IssuedAt         int64  `json:"iat"`
	Type             string `json:"typ"`
	Nonce            string `json:"nonce"`
	AtHash           string `json:"at_hash"`
	ClientID         string `json:"cid,omitempty"`
	UserID           string `json:"uid,omitempty"`
	TenantID         string `json:"tenantId"`
	AuthorizedParty  string `json:"azp"`
	KeycloakClientID string `json:"clientId"`
	// IsHPE is true if the token represents a user from the hpe.com domain, false otherwise
	//
	// Deprecated: The IsHPE field is deprecated and will be removed in a future release!
	IsHPE bool `json:"isHPE"`
}
