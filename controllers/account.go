package controllers

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"

	"sso/core"
	"sso/helper"
	"sso/models"
)

type ReqRefreshToken struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
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
	var data core.UIdData

	var req ReqUpdateProfile
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// get oauth server from ctx
	uidCtx, existed := c.Get("uid")
	if !existed {
		err = fmt.Errorf("not found uid in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	uidStr := uidCtx.(string)
	if len(uidStr) == 0 {
		err = fmt.Errorf("empty uid in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	helper.GetLogger().Debug("update profile for uid %d", uid)
	var account models.Account
	if err := models.DB.Joins("AccountGoogle").Where("accounts.uid=?", uid).First(&account).Error; err != nil {
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

	data, err = models.CreateUidDataFromAccount(&account)
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
	var data core.UIdData

	// get uid from ctx
	uidCtx, existed := c.Get("uid")
	if !existed {
		err = fmt.Errorf("not found uid in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	uid := uidCtx.(string)

	if len(uid) == 0 {
		err = fmt.Errorf("not found uid in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	helper.GetLogger().Debug("get profile for uid %s", uid)
	var account models.Account
	if err := models.DB.Joins("AccountGoogle").Joins("AccountTwitter").Joins("AccountTelegram").Where("accounts.uid=?", uid).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	data, err = models.CreateUidDataFromAccount(&account)
	if err != nil {
		helper.GetLogger().Error("encoding resp data failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "get profile success", "data": data,
		"google": account.AccountGoogle,
	})
}

// @Summary GetProfileByUid
// @ID GetProfileByUid
// @Security ClientBasicAuth
// @Produce application/json
// @Param uid path string true "uid"
// @Success 200 {string} application/json
// @Router /get_profile_by_uid/:uid [get]
func GetProfileByUid(c *gin.Context) {
	var err error
	var data core.UIdData

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

	uid := c.Param("uid")
	if len(uid) == 0 {
		err = fmt.Errorf("not found uid in context")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	helper.GetLogger().Debug("get profile for uid %s", uid)
	var account models.Account
	if err := models.DB.Joins("AccountGoogle").Joins("AccountTwitter").Joins("AccountTelegram").Where("accounts.uid=?", uid).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	data, err = models.CreateUidDataFromAccount(&account)
	if err != nil {
		helper.GetLogger().Error("encoding resp data failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": -3, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "get profile success", "data": data,
		"google": account.AccountGoogle,
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

	uidStr := c.MustGet("uid").(string)
	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("uid invalid").Error()})
		return
	}
	var account models.Account
	if err = models.GetAccountRepository().GetAccountByUid(uid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("not found uid %d", uid)})
		return
	}

	maxNumber, err := strconv.ParseInt(os.Getenv("API_KEY_MAX_NUMBER"), 10, 64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("max number key error %s", err).Error()})
		return
	}

	var secrets []models.AccountSecret
	if err = models.GetAccountRepository().GetAPIKey(&account, &secrets); err != nil {
		helper.GetLogger().Debug("not found api-key of uid %d, create new one", account.Uid)
	} else {
		if len(secrets) >= int(maxNumber) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("account %d has reached max number of key", account.Uid).Error()})
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

	uidStr := c.MustGet("uid").(string)
	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("uid invalid").Error()})
		return
	}

	var account models.Account
	if err = models.GetAccountRepository().GetAccountByUid(uid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("not found uid %d", uid).Error()})
		return
	}

	var secrets []models.AccountSecret
	if err := models.GetAccountRepository().GetAPIKey(&account, &secrets); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Errorf("not found secret account %d", uid).Error()})
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

	uidStr := c.MustGet("uid").(string)
	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("uid invalid").Error()})
		return
	}
	var account models.Account
	if err = models.GetAccountRepository().GetAccountByUid(uid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Errorf("not found uid %d", uid).Error()})
		return
	}
	var secret models.AccountSecret
	if err := models.GetAccountRepository().GetAPIKeyByAccountAndID(&account, req.SecretID, &secret); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("not found secret id %d of uid %d", req.SecretID, uid).Error()})
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
