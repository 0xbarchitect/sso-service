package models

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

var (
	_clientRepositoryIns *ClientRepository
)

func GetClientRepository() *ClientRepository {
	mu.Lock()
	defer mu.Unlock()
	return _clientRepositoryIns
}

func SetClientRepository(r *ClientRepository) {
	mu.Lock()
	defer mu.Unlock()
	_clientRepositoryIns = r
}

type ClientRepository struct {
}

func (r *ClientRepository) GetOauthClients() (*[]Client, error) {
	//var cli []oauthmodels.Client
	var clients []Client
	if err := DB.Where("client_id is not null and client_secret is not null and is_deleted=0").Order("id").Find(&clients).Error; err != nil {
		return nil, err
	}
	return &clients, nil
}

func (r *ClientRepository) GetGinAccounts() (*gin.Accounts, error) {
	accounts := gin.Accounts{}
	var clients []Client
	if err := DB.Where("client_id is not null and client_secret is not null and is_deleted=0").Find(&clients).Error; err != nil {
		return nil, err
	}

	if len(clients) == 0 {
		return nil, fmt.Errorf("not found authorized client")
	}

	for _, c := range clients {
		accounts[c.ClientId] = c.ClientSecret
	}

	return &accounts, nil
}

func (r *ClientRepository) GetClientByClientId(clientId string, client *Client) error {
	return DB.Where("client_id=?", clientId).First(&client).Error
}

func (r *ClientRepository) GetClientById(id int64, cli *Client) error {
	return DB.Where("id=?", id).First(&cli).Error
}

func (r *ClientRepository) CreateClient(name string, description string, clientId string, clientSecret string, redirectUrl string, scope string, isSystem int32) (int64, error) {
	client := Client{
		Name:         name,
		Description:  description,
		ClientId:     clientId,
		ClientSecret: clientSecret,
		RedirectUrl:  redirectUrl,
		Scope:        scope,
		IsSystem:     &isSystem,
		// CreatedAt:    time.Now(),
		// UpdatedAt:    time.Now(),
		// IsDeleted:    0,
	}
	if err := DB.Create(&client).Error; err != nil {
		return 0, err
	}
	return client.ID, nil
}
