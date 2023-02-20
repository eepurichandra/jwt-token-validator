package main

import (
	"context"

	"github.com/hpe-hcss/loglib/pkg/log"

	"github.com/eepurichandra/jwt-token-validator/pkg/token-validator"
)

func main() {
	ctx := context.Background()
	tokenString := "<put your string here>"
	err := token_validator.ValidateToken(ctx, tokenString)
	if err != nil {
		log.Error(ctx, err)
		return
	}
	log.Infof(ctx, "Token is valid")
}
