package helper

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	EIP1271 "sso/helper/abis"

	"golang.org/x/crypto/bcrypt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}

func NewSHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func VerifySignedMessage(hash []byte, signature []byte, signer string) error {
	sigPubkey, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return fmt.Errorf("ecrecover failed %s", err)
	}
	// fmt.Println("SIG PUBKEY:", hexutil.Encode(sigPubkey))

	// get the address to confirm it's the same one in the auth token
	pubkey, err := crypto.UnmarshalPubkey(sigPubkey)
	if err != nil {
		return fmt.Errorf("get pubkey error: %w", err)
	}
	address := crypto.PubkeyToAddress(*pubkey)
	// fmt.Println("ADDRESS:", address.Hex())
	//helper.GetLogger().Debug("wallet address %s", address.Hex())

	if strings.ToLower(signer) != strings.ToLower(address.Hex()) {
		return fmt.Errorf("decoded address %s is not matched with signer %s", address.Hex(), signer)
	}

	return nil
}

func VerifyEIP1271SignedMessage(hash string, signature string, signer string, rpcEndpoint string) error {
	GetLogger().Debug("rpc %s", rpcEndpoint)

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return err
	}

	address := common.HexToAddress(signer)
	instance, err := EIP1271.NewEIP1271(address, client)
	if err != nil {
		return err
	}

	var hash32 [32]byte
	copy(hash32[:], hash)

	var signByte []byte
	copy(signByte, signature)

	signatureBytes, _ := hexutil.Decode(signature)

	GetLogger().Debug("hash %s", common.HexToHash(hash))
	GetLogger().Debug("sign %s", signatureBytes)

	_, err = instance.IsValidSignature(nil, common.HexToHash(hash), signatureBytes)
	if err != nil {
		return err
	}

	return nil
}

func IsValidWalletAddress(address string) bool {
	if len(address) != 42 {
		return false
	}
	match, _ := regexp.MatchString("0x[0-9a-zA-Z]{40}", address)
	return match
}

func HashSignedMessage(message string) string {
	rawData := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message))
	challengeHash := crypto.Keccak256Hash(rawData)
	hash := challengeHash.String()
	return hash
}

func SignMessageWithPrivKey(msg string, privKey string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privKey)
	if err != nil {
		return "", err
	}
	hash := crypto.Keccak256Hash([]byte(msg))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", err
	}
	// update the recovery id https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] += 27
	return hexutil.Encode(signature), nil
}

func SignHashWithPrivKey(hashString string, privKey string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privKey)
	if err != nil {
		return "", err
	}
	hash, err := hexutil.Decode(hashString)
	if err != nil {
		return "", err
	}

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return "", err
	}
	// update the recovery id https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] += 27
	return hexutil.Encode(signature), nil
}
