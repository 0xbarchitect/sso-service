package models

import (
	"fmt"

	"sso/core"
)

// helpers function
func CreateDareidDataFromAccount(account *Account) (core.DareIdData, error) {
	return core.DareIdData{
		Id:            account.ID,
		Dareid:        fmt.Sprintf("%d", account.Dareid),
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
