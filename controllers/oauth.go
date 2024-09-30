package controllers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"sso/helper"
	"sso/models"

	ginSession "github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/errors"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
)

// @Summary OauthTokenHandler
// @ID OauthTokenHandler
// @Security ClientBasicAuth
// @Produce application/json
// @Accept application/x-www-form-urlencoded
// @Param grant_type formData string true "Grant type, eg.: client_credentials, password, authorization_code, refresh_token"
// @Param code formData string false "authorization code"
// @Param redirect_uri formData string false "client's redirect uri"
// @Param code_verifier formData string false "PKCE code verifier"
// @Param refresh_token formData string false "refresh token"
// @Param scope formData string false "scope of refreshing token"
// @Param username formData string false "password gt: username"
// @Param password formData string false "password gt: password"
// @Success 200 {string} application/json
// @Router /oauth/token [post]
func OauthTokenHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("oauth-token recovered from error %s", r)
		}
	}()

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

	w := c.Writer
	r := c.Request

	helper.GetLogger().Debug("start handle request")
	err := srv.HandleTokenRequest(w, r)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
}

// @Summary OauthAuthorizeHandler
// @ID OauthAuthorizeHandler
// @Produce application/json
// @Success 200 {string} application/json
// @Router /oauth/authorize [get]
// @Router /oauth/authorize [post]
func OauthAuthorizeHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("oauth-authorize recovered from error %s", r)
		}
	}()

	var err error
	// get oauth server from ctx
	srvCtx := c.MustGet("oauthServer")
	srv := srvCtx.(*server.Server)

	if srv == nil {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// start session
	ginStore := ginSession.Default(c)

	w := c.Writer
	r := c.Request

	var form url.Values

	dareid := ginStore.Get(LOGGED_UID_KEY)
	if dareid != nil {
		// already logged in
		helper.GetLogger().Debug("found logged in user in session %s", dareid.(string))
		v := ginStore.Get(RETURN_URI_KEY)
		if v != nil {
			helper.GetLogger().Debug("get return uri from session success %T", v)
			form = v.(url.Values)
			r.Form = form
		}
		injectedCtx := context.WithValue(r.Context(), LOGGED_UID_KEY, dareid.(string))
		r = r.WithContext(injectedCtx)

		// cleanup uid & query string params from session to enable to redirect back to client
		ginStore.Delete(LOGGED_UID_KEY)
		ginStore.Delete(RETURN_URI_KEY)
		ginStore.Save()
	} else {
		// not logged in yet
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				panic(fmt.Sprintf("parse form error %s", err))
			}
		}

		helper.GetLogger().Debug("save return uri to session with values %s session id %s", r.Form, ginStore.ID())
		ginStore.Set(RETURN_URI_KEY, r.Form)
		ginStore.Save()

		state := r.FormValue("state")
		injectedCtx := context.WithValue(r.Context(), "state", state)
		r = r.WithContext(injectedCtx)
	}

	helper.GetLogger().Debug("start handler request")
	err = srv.HandleAuthorizeRequest(w, r)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
}

// oauth handlers
func UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("user-authorize recovered from error %s", r)
		}
	}()

	helper.GetLogger().Debug("check existing user in session")
	dareid := r.Context().Value(LOGGED_UID_KEY)
	if dareid == nil {
		// not logged in, redirect based on client's initial state
		state := r.Context().Value("state")
		if state == "signup" {
			helper.GetLogger().Debug("found state signup, redirect to signup page...")
			w.Header().Set("Location", "/signup")
			w.WriteHeader(http.StatusFound)
			return
		}

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	// already logged in, move on to redirect back to client
	userID = dareid.(string)
	return
}

func ValidateClientRedirectURI(authorizedURI string, redirectURI string) error {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}
	redirectOrigUri := fmt.Sprintf("%s://%s%s", redirect.Scheme, redirect.Host, redirect.Path)
	helper.GetLogger().Debug("redirect uri %s", redirectOrigUri)

	// explode base uri to array uris
	uris := strings.Split(authorizedURI, ",")
	// trimming space
	for idx, uri := range uris {
		uris[idx] = strings.TrimSpace(uri)
	}
	helper.GetLogger().Debug("authorized uris %s", uris)

	for _, uri := range uris {
		_, err := url.Parse(uri)
		if err != nil {
			return err
		}

		if uri == redirectOrigUri {
			helper.GetLogger().Debug("found authorized uri %s matched with redirect uri %s", uri, redirectURI)
			return nil
		}
	}

	return errors.ErrInvalidRedirectURI
}

func PasswordAuthorizationHandler(ctx context.Context, clientID, username, password string) (userID string, err error) {
	helper.GetLogger().Debug("password authorization with client %s username %s password %s", clientID, username, password)
	var acct models.Account
	if err := models.GetAccountRepository().GetAccountByAPIKey(password, &acct); err != nil {
		return "", err
	}

	return fmt.Sprintf("%d", acct.Dareid), nil
}

type ReqIssueTokenForDareid struct {
	Dareid string `json:"dareid" binding:"required"`
	Data   string `json:"data"`
}

// @Deprecated
// @Summary IssueTokenForDareidWithData - this API is deprecated, please use /oauth/token instead
// @ID IssueTokenForDareidWithData
// @Security ClientBasicAuth
// @Produce application/json
// @Param _ body ReqIssueTokenForDareid false "issue token for dareid req body"
// @Success 200 {string} application/json
// @Router /oauth/token-with-data [post]
func IssueTokenForDareidWithData(c *gin.Context) {
	var err error

	var req ReqIssueTokenForDareid
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

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

	// validate dareid
	dareid, err := strconv.ParseInt(req.Dareid, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "dareid must be number"})
		return
	}
	var account models.Account
	if err := models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Errorf("dareid %s not exists", req.Dareid).Error()})
		return
	}

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

	// oauth2 token
	gt := oauth2.GrantType("password")
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     client.ClientId,
		ClientSecret: client.ClientSecret,
		Request:      c.Request,
		Scope:        req.Data,
		UserID:       req.Dareid,
	}
	ti, err := srv.GetAccessToken(c.Request.Context(), gt, tgr)
	if err != nil {
		helper.GetLogger().Error("get oauth token failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "get success", "oauth": srv.GetTokenData(ti)})
}

// @Summary ValidateToken
// @ID ValidateToken
// @Produce application/json
// @Param access_token query string true "oauth token"
// @Success 200 {string} application/json
// @Router /oauth/validate-token [get]
func ValidateToken(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("validate-token recovered from error %s", r)
		}
	}()

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

	ti, err := srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":      0,
		"message":   "validation success",
		"dareid":    ti.GetUserID(),
		"client_id": ti.GetClientID(),
		"oauth":     srv.GetTokenData(ti),
	})
}
