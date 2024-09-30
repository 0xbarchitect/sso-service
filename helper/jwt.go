package helper

import (
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/golang-jwt/jwt/v4"
)

const (
	JWT_ISSUER = "dareplay"
)

var (
	_jwtHelperIns JWTHelperInf
)

func SetJwtHelper(ins JWTHelperInf) {
	mu.Lock()
	defer mu.Unlock()
	_jwtHelperIns = ins
}

func GetJwtHelper() JWTHelperInf {
	mu.Lock()
	defer mu.Unlock()
	return _jwtHelperIns
}

func NewJWTHelper(secretKey string) *JWTHelper {
	return &JWTHelper{SecretKey: secretKey}
}

type JWTHelperInf interface {
	ValidateToken(tokenString string) (*generates.JWTAccessClaims, error)
	CreateCustomToken(dareid string, data string, expiresAfter time.Duration) (string, error)
	ParseCustomToken(tokenStr string) (*CustomClaims, error)
}

type CustomClaims struct {
	DareID string `json:"dareid"`
	Data   string `json:"data"`
	jwt.RegisteredClaims
}

type JWTHelper struct {
	SecretKey string
}

func (j *JWTHelper) ValidateToken(tokenString string) (*generates.JWTAccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte(j.SecretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*generates.JWTAccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}
	return claims, nil
}

func (j *JWTHelper) CreateCustomToken(dareid string, data string, expiresAfter time.Duration) (string, error) {
	claims := CustomClaims{
		dareid,
		data,
		jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresAfter)),
			Issuer:    JWT_ISSUER,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(j.SecretKey))
}

func (j *JWTHelper) ParseCustomToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte(j.SecretKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}
	return claims, nil
}
