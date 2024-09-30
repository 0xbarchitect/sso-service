package models

import (
	"time"
)

type DareModel struct {
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	IsDeleted *int32    `gorm:"default:0"`
}

type Client struct {
	ID           int64  `json:"id" gorm:"primary_key"`
	Name         string `gorm:"size:512;not null"`
	Description  string `gorm:"default:null"`
	ClientId     string `gorm:"size:128;unique"`
	ClientSecret string `gorm:"size:128"`
	RedirectUrl  string `gorm:"default:null"`
	Scope        string `gorm:"default:null"`
	IsSystem     *int32 `gorm:"default:0"`
	IsGamer      *int32 `gorm:"default:0"`
	IsGame       *int32 `gorm:"default:0"`
	IsGuild      *int32 `gorm:"default:0"`

	DareModel
}

type Account struct {
	ID            int64   `json:"id" gorm:"primary_key"`
	Uid           int64   `gorm:"uniqueIndex;not null"`
	WalletAddress *string `gorm:"uniqueIndex;size:64;default:null"`
	Name          *string `gorm:"size:512;default:null"`
	Email         *string `gorm:"uniqueIndex;size:512;default:null"`
	Phone         *string `gorm:"size:32;default:null"`
	PasswordHash  *string `gorm:"size:256;default:null"`
	Username      *string `gorm:"size:128;default:null"`
	Description   *string `gorm:"default:null"`
	AvatarUrl     *string `gorm:"size:1024;default:null"`
	EmailVerified *int32  `gorm:"default:0"`

	AccountGoogle AccountGoogle

	DareModel
}

type AccountGoogle struct {
	ID        int64 `json:"id" gorm:"primary_key"`
	Uid       int64 `gorm:"uniqueIndex;not null"`
	AccountID int64

	Sub           string `gorm:"size:64;default:null"`
	Name          string `gorm:"size:1024;default:null"`
	GivenName     string `gorm:"size:512;default:null"`
	FamilyName    string `gorm:"size:512;default:null"`
	Profile       string `gorm:"size:1024;default:null"`
	Picture       string `gorm:"size:1024;default:null"`
	Email         string `gorm:"size:512;default:null"`
	EmailVerified *int32 `gorm:"default:0"`
	Gender        string `gorm:"size:32;default:null"`

	DareModel
}

type Challenge struct {
	ID         int64  `json:"id" gorm:"primary_key"`
	Wallet     string `gorm:"size:42;not null"`
	ChainId    string `gorm:"size:16"`
	Nonce      string `gorm:"size:64;not null;uniqueIndex"`
	Hash       string `gorm:"size:128;not null"`
	ExpiredAt  time.Time
	IsVerified int32 `gorm:"default:0"`
	VerifiedAt time.Time
	Signature  string `gorm:"size:132"`

	DareModel
}

func (Challenge) TableName() string {
	return "challenges"
}

type AccountSecret struct {
	ID        int64 `json:"id" gorm:"primary_key"`
	AccountID int64
	ApiKey    string    `gorm:"size:64;not null;unique"`
	ExpiredAt time.Time `gorm:"default:null"`

	DareModel
}

func (AccountSecret) TableName() string {
	return "account_secrets"
}

type ChainConfig struct {
	ID      int64  `json:"id" gorm:"primary_key"`
	Name    string `gorm:"size:256;not null"`
	ChainId string `gorm:"size:16;not null"`
	Rpc     string `gorm:"size:512;not null"`

	DareModel
}

func (ChainConfig) TableName() string {
	return "chain_config"
}
