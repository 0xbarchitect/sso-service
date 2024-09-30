package models

import (
	"fmt"

	"sso/core"
)

// helpers function
func CreateUidDataFromAccount(account *Account) (core.UIdData, error) {
	return core.UIdData{
		Id:            account.ID,
		Uid:           fmt.Sprintf("%d", account.Uid),
		WalletAddress: account.WalletAddress,
		Name:          account.Name,
		Email:         account.Email,
		Phone:         account.Phone,
		Username:      account.Username,
		Description:   account.Description,
		AvatarUrl:     account.AvatarUrl,
		EmailVerified: account.EmailVerified,
		CreatedAt:     account.CreatedAt.String(),
		UpdatedAt:     account.UpdatedAt.String(),
	}, nil
}
