package helper

import (
	"net/mail"
	"regexp"
)

func EmailValid(email string) bool {
	var err error
	_, err = mail.ParseAddress(email)
	if err != nil {
		return false
	}
	// validate business email
	pattern := "^\\w+([-+.]\\w+)*@(yahoo|gmail|hotmail)\\.com"
	r, _ := regexp.Compile(pattern)
	return !r.MatchString(email)
}

func WalletAddressValid(address string) bool {
	pattern := "^0x[a-fA-F0-9]{40}$"
	r, _ := regexp.Compile(pattern)
	return r.MatchString(address)
}
