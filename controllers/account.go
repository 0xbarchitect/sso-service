package controllers

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"

	"sso/core"
	"sso/helper"
	"sso/models"
	"sso/service"
)

// @Deprecated
// @Summary GetDareIdByWalletAddress
// @ID GetDareIdByWalletAddress
// @Security ClientBasicAuth
// @Produce application/json
// @Param wallet_address path string true "wallet address"
// @Success 200 {string} application/json
// @Router /get_dareid_by_wallet_address/{wallet_address} [get]
func GetDareIdByWalletAddress(c *gin.Context) {
	var data core.DareIdData
	var account models.Account
	var err error
	var isCreated bool

	// get oauth server from ctx
	srvCtx, existed := c.Get("oauthServer")

	if !existed {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	srv := srvCtx.(*server.Server)
	if srv == nil {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	walletAddr := c.Param("wallet_address")
	helper.GetLogger().Debug("find dareid by wallet address %s", walletAddr)
	walletAddr = strings.ToLower(walletAddr)

	if !helper.WalletAddressValid(walletAddr) {
		err := fmt.Errorf("wallet address is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err = models.DB.Where("wallet_address = ?", walletAddr).First(&account).Error; err != nil {
		helper.GetLogger().Debug("not found dareid by wallet address %s, create new one ...", walletAddr)

		dareid, err := service.GetSFGenerator().GenerateID()
		if err != nil {
			helper.GetLogger().Error("generator dareid failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -2, "error": err.Error()})
			return
		}
		helper.GetLogger().Debug("generated new dareid %d", dareid)
		name := "auto-created"
		account = models.Account{
			Dareid:        dareid,
			WalletAddress: &walletAddr,
			Name:          &name,
			// CreatedAt:     time.Now(),
			// UpdatedAt:     time.Now(),
			// IsDeleted:     0,
		}

		if err := models.DB.Create(&account).Error; err != nil {
			msg := fmt.Sprintf("create new account failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "message": msg})
			return
		} else {
			helper.GetLogger().Debug("created new account with id %d", account.ID)
			isCreated = true
			data, err = models.CreateDareidDataFromAccount(&account)
			if err != nil {
				helper.GetLogger().Error("encoding resp data failed with error %s", err)
				c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
				return
			}
		}
	} else {
		data, err = models.CreateDareidDataFromAccount(&account)
		if err != nil {
			helper.GetLogger().Error("encoding resp data failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
			return
		}
	}

	// oauth2 token
	clientId := c.MustGet(gin.AuthUserKey).(string)
	var client models.Client
	if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
		helper.GetLogger().Error("not found client %s", clientId)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	helper.GetLogger().Debug("found client id %d with client_id %s and secret %s", client.ID, client.ClientId, client.ClientSecret)

	gt := oauth2.GrantType("password")
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     client.ClientId,
		ClientSecret: client.ClientSecret,
		Request:      c.Request,
		Scope:        "all",
		UserID:       data.Dareid,
	}
	ti, err := srv.GetAccessToken(c.Request.Context(), gt, tgr)
	if err != nil {
		helper.GetLogger().Error("get oauth token failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	httpStatus := http.StatusOK
	if isCreated {
		httpStatus = http.StatusCreated
	}

	c.JSON(httpStatus, gin.H{"code": 0, "message": "get success", "data": data, "oauth": srv.GetTokenData(ti)})
}

type ReqRefreshToken struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// @Deprecated
// @Summary RefreshToken - this API is deprecated, please use /oauth/token instead
// @ID RefreshToken
// @Security ClientBasicAuth
// @Produce application/json
// @Param _ body ReqRefreshToken false "refresh token req body"
// @Success 200 {string} application/json
// @Router /refresh_token [post]
func RefreshToken(c *gin.Context) {
	var err error
	var req ReqRefreshToken
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// get oauth server from ctx
	srvCtx, existed := c.Get("oauthServer")

	if !existed {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	srv := srvCtx.(*server.Server)

	if srv == nil {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// oauth2 token
	clientId := c.MustGet(gin.AuthUserKey).(string)
	var client models.Client
	if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
		helper.GetLogger().Error("not found client %s", clientId)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	//gt := oauth2.GrantType("refresh_token")
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientId,
		ClientSecret: client.ClientSecret,
		Request:      c.Request,
		Refresh:      req.RefreshToken,
		Scope:        "all",
	}
	//ti, err := srv.GetAccessToken(c.Request.Context(), gt, tgr)
	ti, err := srv.Manager.RefreshAccessToken(c.Request.Context(), tgr)
	if err != nil {
		helper.GetLogger().Error("get oauth token failed with error %s", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "refresh token success", "oauth": srv.GetTokenData(ti)})
}

type ReqUpdateProfile struct {
	Username    string `json:"username"`
	Description string `json:"description"`
	AvatarURL   string `json:"avatar_url"`
}

// @Summary UpdateProfile
// @ID UpdateProfile
// @Security JwtHeader
// @Produce application/json
// @Param _ body ReqUpdateProfile false "update profile json body"
// @Success 200 {string} application/json
// @Router /update_profile [post]
func UpdateProfile(c *gin.Context) {
	var err error
	var data core.DareIdData

	var req ReqUpdateProfile
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// get oauth server from ctx
	dareidCtx, existed := c.Get("dareid")
	if !existed {
		err = fmt.Errorf("not found dareid in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	dareidStr := dareidCtx.(string)
	if len(dareidStr) == 0 {
		err = fmt.Errorf("empty dareid in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	helper.GetLogger().Debug("update profile for dareid %d", dareid)
	var account models.Account
	if err := models.DB.Joins("AccountGoogle").Where("accounts.dareid=?", dareid).First(&account).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if req.Username != "" {
		account.Username = &req.Username
	}
	if req.AvatarURL != "" {
		account.AvatarUrl = &req.AvatarURL
	}
	if req.Description != "" {
		account.Description = &req.Description
	}
	if err := models.DB.Save(&account).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	data, err = models.CreateDareidDataFromAccount(&account)
	if err != nil {
		helper.GetLogger().Error("encoding resp data failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "update profile success", "data": data})
}

// @Summary GetProfile
// @ID GetProfile
// @Security JwtHeader
// @Produce application/json
// @Success 200 {string} application/json
// @Router /get_profile [get]
func GetProfile(c *gin.Context) {
	var err error
	var data core.DareIdData

	// get dareid from ctx
	dareidCtx, existed := c.Get("dareid")
	if !existed {
		err = fmt.Errorf("not found dareid in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	dareid := dareidCtx.(string)

	if len(dareid) == 0 {
		err = fmt.Errorf("not found dareid in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	helper.GetLogger().Debug("get profile for dareid %s", dareid)
	var account models.Account
	if err := models.DB.Joins("AccountGoogle").Joins("AccountTwitter").Joins("AccountTelegram").Where("accounts.dareid=?", dareid).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	data, err = models.CreateDareidDataFromAccount(&account)
	if err != nil {
		helper.GetLogger().Error("encoding resp data failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "get profile success", "data": data,
		"google":   account.AccountGoogle,
		"twitter":  account.AccountTwitter,
		"telegram": account.AccountTelegram,
	})
}

// @Summary GetProfileByDareid
// @ID GetProfileByDareid
// @Security ClientBasicAuth
// @Produce application/json
// @Param dareid path string true "dareid"
// @Success 200 {string} application/json
// @Router /get_profile_by_dareid/:dareid [get]
func GetProfileByDareid(c *gin.Context) {
	var err error
	var data core.DareIdData

	// only system client could call this api
	clientId := c.MustGet(gin.AuthUserKey).(string)
	var client models.Client
	if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
		helper.GetLogger().Error("client %s is not found", clientId)
		err = fmt.Errorf("client id is not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if *client.IsSystem != int32(1) {
		helper.GetLogger().Error("client %s is unauthorized to access this api", clientId)
		err = fmt.Errorf("client is unauthorized")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	dareid := c.Param("dareid")
	if len(dareid) == 0 {
		err = fmt.Errorf("not found dareid in context")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	helper.GetLogger().Debug("get profile for dareid %s", dareid)
	var account models.Account
	if err := models.DB.Joins("AccountGoogle").Joins("AccountTwitter").Joins("AccountTelegram").Where("accounts.dareid=?", dareid).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	data, err = models.CreateDareidDataFromAccount(&account)
	if err != nil {
		helper.GetLogger().Error("encoding resp data failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "get profile success", "data": data,
		"google":   account.AccountGoogle,
		"twitter":  account.AccountTwitter,
		"telegram": account.AccountTelegram,
	})
}

type CreateAPIKeyResp struct {
	SuccessResp
	Secret models.AccountSecret `json:"secret"`
}

// @Summary Create API Key
// @ID CreateAPIKey
// @Security JwtHeader
// @Produce application/json
// @Success 200 {object} CreateAPIKeyResp
// @Failure 400 {object} BadRequestResp
// @Failure 500 {object} ServerErrorResp
// @Router /create-api-key [post]
func CreateAPIKey(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("create-api-key recovered from error %s", r)
		}
	}()

	dareidStr := c.MustGet("dareid").(string)
	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("dareid invalid").Error()})
		return
	}
	var account models.Account
	if err = models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("not found dareid %d", dareid)})
		return
	}

	maxNumber, err := strconv.ParseInt(os.Getenv("API_KEY_MAX_NUMBER"), 10, 64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("max number key error %s", err).Error()})
		return
	}

	var secrets []models.AccountSecret
	if err = models.GetAccountRepository().GetAPIKey(&account, &secrets); err != nil {
		helper.GetLogger().Debug("not found api-key of dareid %d, create new one", account.Dareid)
	} else {
		if len(secrets) >= int(maxNumber) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("account %d has reached max number of key", account.Dareid).Error()})
			return
		}
	}

	secret, err := models.GetAccountRepository().CreateAPIKey(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("create api key error %s", err).Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "create api-key success", "secret": secret})
}

type GetAPIKeyResp struct {
	SuccessResp
	Secrets []models.AccountSecret `json:"secrets"`
}

// @Summary Get API Key
// @ID GetAPIKey
// @Security JwtHeader
// @Produce application/json
// @Success 200 {object} GetAPIKeyResp
// @Failure 400 {object} BadRequestResp
// @Failure 500 {object} ServerErrorResp
// @Router /get-api-key [get]
func GetAPIKey(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("create-api-key recovered from error %s", r)
		}
	}()

	dareidStr := c.MustGet("dareid").(string)
	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("dareid invalid").Error()})
		return
	}

	var account models.Account
	if err = models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("not found dareid %d", dareid).Error()})
		return
	}

	var secrets []models.AccountSecret
	if err := models.GetAccountRepository().GetAPIKey(&account, &secrets); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Errorf("not found secret account %d", dareid).Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "get api-key success", "secrets": secrets})
}

type DeleteAPIKeyReq struct {
	SecretID int64 `json:"secret_id"`
}

// @Summary Delete API Key
// @ID DeleteAPIKey
// @Security JwtHeader
// @Produce application/json
// @Param _ body DeleteAPIKeyReq true "json body"
// @Success 200 {object} SuccessResp
// @Failure 400 {object} BadRequestResp
// @Failure 500 {object} ServerErrorResp
// @Router /delete-api-key [delete]
func DeleteAPIKey(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("create-api-key recovered from error %s", r)
		}
	}()

	var req DeleteAPIKeyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("parsing req body error %s", err).Error()})
		return
	}

	dareidStr := c.MustGet("dareid").(string)
	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("dareid invalid").Error()})
		return
	}
	var account models.Account
	if err = models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("not found dareid %d", dareid).Error()})
		return
	}
	var secret models.AccountSecret
	if err := models.GetAccountRepository().GetAPIKeyByAccountAndID(&account, req.SecretID, &secret); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("not found secret id %d of dareid %d", req.SecretID, dareid).Error()})
		return
	}

	if err := models.GetAccountRepository().DeleteAPIKey(&secret); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("delete api key error %s", err).Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "delete api-key success"})
}

type RegistAccountReq struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
}

// @Summary RegistAccountHandler
// @ID RegistAccountHandler
// @Produce application/json
// @Success 200 {string} application/json
// @Param _ body RegistAccountReq true "json body"
// @Router /regist-account [post]
func RegistAccountHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("signup recovered from panic %s", r)
		}
	}()

	var req RegistAccountReq
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.GetLogger().Error("parsing req body failed with error %s", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Password) < PASSWORD_LENGTH_MINIMUM {
		helper.GetLogger().Error("password %s is too short", req.Password)
		err := fmt.Errorf("password is too short")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	account := core.AccountAPI{
		Email:     req.Email,
		Password:  req.Password,
		Username:  req.Username,
		AvatarUrl: req.Avatar,
	}

	result, err := models.GetAccountRepository().CreateUserByAPI(account)
	if err != nil {
		helper.GetLogger().Error("create user failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	helper.GetLogger().Debug("create user succeed with id %d", result.ID)
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "create user succeed"})
}
