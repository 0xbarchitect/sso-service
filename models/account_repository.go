package models

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sso/core"
	"sso/helper"
	"sso/service"
)

var (
	accountRepositoryIns *AccountRepository
	mu                   sync.Mutex
)

func GetAccountRepository() *AccountRepository {
	mu.Lock()
	defer mu.Unlock()
	return accountRepositoryIns
}

func SetAccountRepository(r *AccountRepository) {
	mu.Lock()
	defer mu.Unlock()
	accountRepositoryIns = r
}

type AccountRepository struct{}

func (AccountRepository) CreateUser(acct core.AccountCore) (int64, error) {
	var exists Account
	if err := DB.Where("email = ?", acct.Email).First(&exists).Error; err != nil {
		helper.GetLogger().Debug("not found existed user with email %s, create new", acct.Email)
	} else {
		return exists.ID, fmt.Errorf("This email is already signed up , try another or forgot password")
	}

	passwordHash, err := helper.HashPassword(acct.Password)
	if err != nil {
		helper.GetLogger().Error("generate password hash failed with error %s", err)
		return 0, err
	}

	dareid, err := service.GetSFGenerator().GenerateID()
	if err != nil {
		helper.GetLogger().Error("generator dareid failed with error %s", err)
		return 0, err
	}

	name := "signup by email password"
	emailVerified := int32(0)
	account := Account{
		Dareid:        dareid,
		Name:          &name,
		Email:         &acct.Email,
		PasswordHash:  &passwordHash,
		EmailVerified: &emailVerified,
		// CreatedAt:     time.Now(),
		// UpdatedAt:     time.Now(),
		// IsDeleted:     0,
	}

	if err := DB.Create(&account).Error; err != nil {
		helper.GetLogger().Debug("create new account failed with error %s", err)
		return 0, err
	}

	helper.GetLogger().Debug("created new account with id %d", account.ID)
	return account.ID, nil
}

func (r *AccountRepository) CreateUserWithWalletAddress(address string) (*Account, error) {
	acctCore := core.AccountCore{WalletAddr: address}
	accountId, err := r.CreateUserByWallet(acctCore)
	if err != nil {
		return nil, err
	}
	acct := Account{}
	if err := r.GetAccountByID(accountId, &acct); err != nil {
		return nil, err
	}
	return &acct, nil
}

func (AccountRepository) CreateUserByWallet(acct core.AccountCore) (int64, error) {
	acct.WalletAddr = strings.ToLower(acct.WalletAddr)

	if len(acct.WalletAddr) == 0 {
		return 0, fmt.Errorf("wallet address empty")
	}

	var exists Account
	if err := DB.Where("wallet_address = ?", acct.WalletAddr).First(&exists).Error; err != nil {
		helper.GetLogger().Debug("not found existed user with wallet address %s, create new", acct.WalletAddr)
	} else {
		helper.GetLogger().Debug("found existed account with id %d", exists.ID)
		return exists.ID, nil
	}

	dareid, err := service.GetSFGenerator().GenerateID()
	if err != nil {
		helper.GetLogger().Error("generator dareid failed with error %s", err)
		return 0, err
	}

	name := "signup by wallet"
	account := Account{
		Dareid:        dareid,
		Name:          &name,
		WalletAddress: &acct.WalletAddr,
		// CreatedAt:     time.Now(),
		// UpdatedAt:     time.Now(),
		// IsDeleted:     0,
	}

	if err := DB.Create(&account).Error; err != nil {
		helper.GetLogger().Debug("create new account failed with error %s", err)
		return 0, err
	}

	helper.GetLogger().Debug("created new account with id %d", account.ID)
	return account.ID, nil
}

func (AccountRepository) CreateUserByGoogle(acct core.GoogleUserInfo) (Account, error) {
	dareid, err := service.GetSFGenerator().GenerateID()
	if err != nil {
		helper.GetLogger().Error("generator dareid failed with error %s", err)
		return Account{}, err
	}

	name := acct.Name
	if len(name) == 0 {
		name = acct.GivenName + " " + acct.FamilyName
	}

	emailVerified := int32(0)
	if acct.EmailVerified {
		emailVerified = int32(1)
	}

	account := Account{
		Dareid:        dareid,
		Name:          &name,
		Email:         &acct.Email,
		EmailVerified: &emailVerified,
		AvatarUrl:     &acct.Picture,
	}

	if err := DB.Create(&account).Error; err != nil {
		helper.GetLogger().Debug("create new account failed with error %s", err)
		return Account{}, err
	}

	helper.GetLogger().Debug("created new account with id %d", account.ID)
	return account, nil
}

func (AccountRepository) CreateUserByAPI(acct core.AccountAPI) (Account, error) {
	var exists Account
	if err := DB.Where("email = ?", acct.Email).First(&exists).Error; err != nil {
		helper.GetLogger().Debug("not found existed user with email %s, create new", acct.Email)
	} else {
		return Account{}, fmt.Errorf("This email is already signed up , try another or forgot password")
	}

	passwordHash, err := helper.HashPassword(acct.Password)
	if err != nil {
		helper.GetLogger().Error("generate password hash failed with error %s", err)
		return Account{}, err
	}

	dareid, err := service.GetSFGenerator().GenerateID()
	if err != nil {
		helper.GetLogger().Error("generator dareid failed with error %s", err)
		return Account{}, err
	}

	name := "register by api"
	emailVerified := int32(1)

	account := Account{
		Dareid:        dareid,
		Name:          &name,
		Email:         &acct.Email,
		PasswordHash:  &passwordHash,
		EmailVerified: &emailVerified,
		AvatarUrl:     &acct.AvatarUrl,
		Username:      &acct.Username,
	}

	if err := DB.Create(&account).Error; err != nil {
		helper.GetLogger().Debug("create new account failed with error %s", err)
		return Account{}, err
	}

	helper.GetLogger().Debug("created new account with id %d", account.ID)
	return account, nil
}

func (AccountRepository) LoginUser(email string, password string) (int64, error) {
	var exists Account
	errMsg := "Email or password is invalid ! Try again."
	if err := DB.Where("email = ?", email).First(&exists).Error; err != nil {
		helper.GetLogger().Debug("not found existed user with email %s, create new", email)
		return 0, fmt.Errorf(errMsg)
	} else {
		helper.GetLogger().Debug("found existed account with id %d", exists.ID)
		if !helper.CheckPasswordHash(password, *exists.PasswordHash) {
			helper.GetLogger().Debug("password mismatched")
			return 0, fmt.Errorf(errMsg)
		}
		return exists.ID, nil
	}
}

func (r *AccountRepository) LoginUserByWallet(wallet_address string) (int64, error) {
	var exists Account
	wallet_address = strings.ToLower(wallet_address)

	if err := DB.Where("wallet_address = ?", wallet_address).First(&exists).Error; err != nil {
		helper.GetLogger().Debug("not found existed user with wallet %s, create new", wallet_address)
		acctCore := core.AccountCore{WalletAddr: wallet_address}
		accountId, err := r.CreateUserByWallet(acctCore)
		if err != nil {
			helper.GetLogger().Error("create user by wallet failed with error %s", err)
			return 0, err
		}
		return accountId, nil
	} else {
		helper.GetLogger().Debug("found existed account with id %d", exists.ID)
		return exists.ID, nil
	}
}

func (AccountRepository) GetAccountByDareid(dareid int64, acct *Account) error {
	return DB.Where("accounts.dareid = ?", dareid).First(acct).Error
}

func (AccountRepository) GetAccountByEmail(email string, acct *Account) error {
	return DB.Where("accounts.email = ?", email).First(acct).Error
}

func (AccountRepository) GetAccountByID(id int64, acct *Account) error {
	return DB.Where("accounts.id = ?", id).First(acct).Error
}

func (AccountRepository) GetAccountByWallet(wallet string, acct *Account) error {
	wallet = strings.ToLower(wallet)
	return DB.Where("accounts.wallet_address = ?", wallet).First(acct).Error
}

func (AccountRepository) GetAccountFullByID(id int64, acct *Account) error {
	return DB.Joins("AccountGoogle").Joins("AccountTwitter").Joins("AccountTelegram").Where("accounts.id=?", id).First(&acct).Error
}

func (AccountRepository) ChangePassword(password string, acct *Account) error {
	passwordHash, err := helper.HashPassword(password)
	if err != nil {
		helper.GetLogger().Error("generate password hash failed with error %s", err)
		return err
	}

	acct.PasswordHash = &passwordHash
	acct.UpdatedAt = time.Now()

	if err := DB.Save(acct).Error; err != nil {
		helper.GetLogger().Error("change password failed with error %s", err)
		return err
	}
	return nil
}

func (AccountRepository) VerifyEmail(acct *Account) error {
	verified := int32(1)
	acct.EmailVerified = &verified
	//acct.UpdatedAt = time.Now()

	return DB.Save(acct).Error
}

func (AccountRepository) CreateChallenge(wallet string, nonce string, hash string, chainId string) (*Challenge, error) {
	expired := time.Now().Add(NONCE_EXPIRATION)

	challenge := Challenge{
		Wallet:    strings.ToLower(wallet),
		ChainId:   chainId,
		Nonce:     nonce,
		Hash:      hash,
		ExpiredAt: expired,
	}
	if err := DB.Create(&challenge).Error; err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (AccountRepository) GetChallengeByHash(hash string, ch *Challenge) error {
	return DB.Where("hash=?", hash).First(ch).Error
}

func (AccountRepository) ValidateNonce(ch *Challenge, isVerified bool) error {
	if *ch.IsDeleted == 1 {
		return fmt.Errorf("nonce is used")
	}
	now := time.Now()
	if ch.ExpiredAt.Unix() > 0 {
		if now.Unix() > ch.ExpiredAt.Unix() {
			return fmt.Errorf("nonce is expired")
		}
	} else {
		if now.Sub(ch.CreatedAt) > NONCE_EXPIRATION {
			return fmt.Errorf("nonce is expired")
		}
	}
	if isVerified {
		if ch.IsVerified != 1 {
			return fmt.Errorf("nonce is not verified")
		}
	}

	return nil
}

func (AccountRepository) InvalidateChallenge(ch *Challenge) error {
	*ch.IsDeleted = 1
	//ch.UpdatedAt = time.Now()
	return DB.Save(ch).Error
}

func (AccountRepository) SetVerifiedChallenge(ch *Challenge, signature string) error {
	ch.IsVerified = 1
	ch.VerifiedAt = time.Now()
	ch.Signature = signature
	//ch.UpdatedAt = time.Now()
	return DB.Save(ch).Error
}

func (AccountRepository) CreateAPIKey(acct *Account) (*AccountSecret, error) {
	length, err := strconv.ParseInt(os.Getenv("API_KEY_LENGTH"), 10, 64)
	if err != nil {
		return nil, err
	}
	key, err := helper.GenerateRandomStringWithLength(int(length))
	if err != nil {
		return nil, err
	}
	daysTTL, err := strconv.ParseInt(os.Getenv("API_KEY_TTL"), 10, 64)
	if err != nil {
		return nil, err
	}
	expiredAt := time.Now().Add(time.Duration(daysTTL*24) * time.Hour)
	secret := AccountSecret{
		AccountID: acct.ID,
		ApiKey:    key,
		ExpiredAt: expiredAt,
	}
	if err := DB.Create(&secret).Error; err != nil {
		return nil, err
	}
	return &secret, nil
}

func (AccountRepository) GetAPIKey(acct *Account, secrets *[]AccountSecret) error {
	return DB.Where("account_id=?", acct.ID).Find(&secrets).Error
}

func (AccountRepository) DeleteAPIKey(secret *AccountSecret) error {
	return DB.Delete(&AccountSecret{}, secret.ID).Error
}

func (AccountRepository) GetAPIKeyByAccountAndID(acct *Account, id int64, secret *AccountSecret) error {
	return DB.Where("account_id=? and id=?", acct.ID, id).First(&secret).Error
}

func (AccountRepository) GetAccountByAPIKey(apiKey string, acct *Account) error {
	var secret AccountSecret
	if err := DB.Where("api_key=? and is_deleted=0", apiKey).First(&secret).Error; err != nil {
		return err
	}

	return DB.Where("id=?", secret.AccountID).First(acct).Error
}

func (AccountRepository) GetChainConfig(chainId string, chainConfig *ChainConfig) error {
	return DB.Where("chain_id=?", chainId).First(&chainConfig).Error
}
