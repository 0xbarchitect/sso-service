package controllers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sso/core"
	"sso/helper"
	"sso/models"
	"sso/service"

	"github.com/sendgrid/rest"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"

	ginSession "github.com/gin-contrib/sessions"
	oauthClient "golang.org/x/oauth2"
)

const (
	PASSWORD_LENGTH_MINIMUM = 6
	OAUTH_AUTH_COOKIE_NAME  = "daresso_auth"
	AUTH_COOKIE_TTL         = 365 * 24 * time.Hour // 1 year
)

func SendEmailVerification(oauthSrv *server.Server, ssoURL string, clientId string, clientSecret string, clientRedirectURL string, codeChallenge string, account models.Account) (*rest.Response, error) {
	if account.Email == nil || !helper.EmailValid(*account.Email) {
		return nil, fmt.Errorf("account email invalid")
	}

	config := oauthClient.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  clientRedirectURL,
		Scopes:       []string{"all"},
		Endpoint: oauthClient.Endpoint{
			AuthURL:  ssoURL + "/signup",
			TokenURL: ssoURL + "/signup",
		},
	}
	redirectURL := config.AuthCodeURL("verify_email",
		oauthClient.SetAuthURLParam("code_challenge", codeChallenge),
		oauthClient.SetAuthURLParam("code_challenge_method", "S256"))

	// oauth2 token
	gt := oauth2.GrantType("password")
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Request:      &http.Request{},
		Scope:        "email_verification",
		UserID:       fmt.Sprintf("%d", account.Dareid),
	}
	ti, err := oauthSrv.GetAccessToken(context.Background(), gt, tgr)
	if err != nil {
		return nil, err
	}

	// send email verification
	return service.GetSendgridService().SendEmailVerification(*account.Email, redirectURL, ti.GetAccess())
}

// @Summary LoginHandler
// @ID LoginHandler
// @Produce multipart/form-data
// @Success 200 {string} text/html
// @Param state formData string false "state"
// @Param username formData string false "username"
// @Param password formData string false "password"
// @Param wallet_address formData string false "wallet_address"
// @Router /login [get]
// @Router /login [post]
func LoginHandler(c *gin.Context) {
	var err error
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("login recovered from error %s", r)
		}
	}()

	// w := c.Writer
	r := c.Request

	ginStore := ginSession.Default(c)

	// i18n
	lng := c.DefaultQuery("lang", "en")

	var form url.Values

	// specify client type
	is_gamer := 0
	is_game := 0
	is_guild := 0

	v := ginStore.Get(RETURN_URI_KEY)
	if v != nil {
		helper.GetLogger().Debug("get return uri from session success %T", v)
		form = v.(url.Values)
		if clientIds, ok := form["client_id"]; ok {
			clientId := clientIds[0]
			var client models.Client
			if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
				helper.GetLogger().Error("get client from db failed with error %s, eg. client demo", err)
			} else {
				helper.GetLogger().Debug("found client in db, check type")
				if client.IsGamer != nil {
					is_gamer = int(*client.IsGamer)
				}
				if client.IsGame != nil {
					is_game = int(*client.IsGame)
				}
				if client.IsGuild != nil {
					is_guild = int(*client.IsGuild)
				}
			}
		}
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
		err := fmt.Errorf("oauth server invalid")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ssoURLCtx, existed := c.Get("ssoURL")
	if !existed {
		err := fmt.Errorf("not found ssoURL in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ssoURL := ssoURLCtx.(string)
	if len(ssoURL) == 0 {
		err := fmt.Errorf("ssoURL is empty")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// specify client manifest
	var clientId, clientSecret, clientRedirectURL, codeChallenge string
	if v != nil {
		helper.GetLogger().Debug("get return uri from session success %T", v)
		form = v.(url.Values)

		if clientIds, ok := form["client_id"]; ok {
			clientId = clientIds[0]
			var client models.Client
			if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
				helper.GetLogger().Error("get client from db failed with error %s, eg. client demo", err)
			} else {
				helper.GetLogger().Debug("found client in db with id %d", client.ID)
				clientSecret = client.ClientSecret

				if redirectURI, ok := form["redirect_uri"]; ok {
					clientRedirectURL = redirectURI[0]
				} else {
					helper.GetLogger().Debug("read redirect uri from db")
					clientRedirectURL = client.RedirectUrl
				}

				if codeChal, ok := form["code_challenge"]; ok {
					codeChallenge = codeChal[0]
				}
			}
		}
	}
	if len(clientId) > 0 && len(clientSecret) > 0 && len(clientRedirectURL) > 0 && len(codeChallenge) > 0 {
		helper.GetLogger().Debug("found client info %s in session", clientId)
		helper.GetLogger().Debug("client id %s redirect uri %s code challenge %s", clientId, clientRedirectURL, codeChallenge)
	} else {
		clientIdCtx := c.MustGet("clientId")
		clientId = clientIdCtx.(string)
		if len(clientId) == 0 {
			err := fmt.Errorf("not found client id in context")
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		clientSecretCtx := c.MustGet("clientSecret")
		clientSecret = clientSecretCtx.(string)
		if len(clientSecret) == 0 {
			err := fmt.Errorf("not found client secret in context")
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		clientRedirectURLCtx := c.MustGet("clientRedirectURL")
		clientRedirectURL = clientRedirectURLCtx.(string)
		if len(clientRedirectURL) == 0 {
			err := fmt.Errorf("not found client redirect url in context")
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		codeChallengeCtx := c.MustGet("codeChallenge")
		codeChallengeStr := codeChallengeCtx.(string)
		codeChallenge = helper.GenCodeChallengeS256(codeChallengeStr)
	}

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

		state := r.Form.Get("state")
		if state == "email_verify" {
			// get dareid from session store
			dareidCtx := ginStore.Get(LOGGED_UID_KEY)
			if dareidCtx == nil {
				helper.GetLogger().Error("not found dareid in session")
				c.Redirect(http.StatusFound, "/login")
				return
			}
			dareidStr := dareidCtx.(string)
			if len(dareidStr) == 0 {
				helper.GetLogger().Error("empty dareid in session")
				c.Redirect(http.StatusFound, "/login")
				return
			}
			dareid, err := strconv.ParseInt(dareidStr, 10, 64)
			if err != nil {
				helper.GetLogger().Error("parsing dareid failed with error %s", err)
				c.Redirect(http.StatusFound, "/login")
				return
			}

			var account models.Account
			if err := models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
				helper.GetLogger().Error("get account from dareid %d failed with error %s", dareid, err)
				c.Redirect(http.StatusFound, "/login")
				return
			}

			result, err := SendEmailVerification(srv, ssoURL, clientId, clientSecret, clientRedirectURL, codeChallenge, account)
			if err != nil {
				helper.GetLogger().Error("send email verification failed with error %s", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			helper.GetLogger().Debug("send email verification succeed with status %d", result.StatusCode)
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"title":        "SSO | Login",
				"email_verify": 2, // verification sent
				"email":        *account.Email,
				"lng":          lng,
			})
			return
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")
		wallet_address := r.Form.Get("wallet_address")
		helper.GetLogger().Debug("login with username %s wallet %s", username, wallet_address)

		var accountId int64
		login_email := false
		if len(wallet_address) > 0 {
			signature := r.Form.Get("signature")
			hash := r.Form.Get("hash")
			helper.GetLogger().Debug("login by wallet %s with sign %s and hash %s", wallet_address, signature, hash)
			challenge, err := VerifyWalletChallenge(hash, signature)
			if err != nil {
				c.HTML(http.StatusNotAcceptable, "login.tmpl", gin.H{
					"title": "SSO | Login",
					"error": err.Error(),
					"lng":   lng,
				})
				return
			}
			if challenge.Wallet != wallet_address {
				helper.GetLogger().Error("challenge wallet %s and requested wallet %s mismatched", challenge.Wallet, wallet_address)
				c.HTML(http.StatusNotAcceptable, "login.tmpl", gin.H{
					"title": "SSO | Login",
					"error": fmt.Errorf("challenge mismatched").Error(),
					"lng":   lng,
				})
				return
			}

			accountId, err = models.GetAccountRepository().LoginUserByWallet(wallet_address)
			if err != nil {
				c.HTML(http.StatusNotAcceptable, "login.tmpl", gin.H{
					"title": "SSO | Login",
					"error": err.Error(),
					"lng":   lng,
				})
				return
			}
		} else {
			helper.GetLogger().Debug("login by email / password")
			login_email = true
			accountId, err = models.GetAccountRepository().LoginUser(username, password)
			if err != nil {
				c.HTML(http.StatusNotAcceptable, "login.tmpl", gin.H{
					"title": "SSO | Login",
					"error": err.Error(),
					"lng":   lng,
				})
				return
			}
		}

		if accountId > 0 {
			var acct models.Account
			if err := models.DB.Where("id = ?", accountId).First(&acct).Error; err != nil {
				helper.GetLogger().Debug("not found existed user with id %d", accountId)
				c.HTML(http.StatusNotAcceptable, "login.tmpl", gin.H{
					"title": "SSO | Login",
					"error": err.Error(),
					"lng":   lng,
				})
				return
			}

			// save dareid into session
			helper.GetLogger().Debug("save uid into session %d", acct.Dareid)
			ginStore.Set(LOGGED_UID_KEY, fmt.Sprintf("%d", acct.Dareid))
			ginStore.Save()

			if login_email {
				if acct.EmailVerified == nil || *acct.EmailVerified == 0 {
					helper.GetLogger().Debug("email is unverified, skip login")
					c.HTML(http.StatusOK, "login.tmpl", gin.H{
						"title":        "SSO | Login",
						"email_verify": 1, // request verification
						"lng":          lng,
					})
					return
				}
			}

			c.Redirect(http.StatusFound, "/auth")
			return
		} else {
			err = fmt.Errorf("not found user")
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"title": "SSO | Login",
				"error": err.Error(),
				"lng":   lng,
			})
			return
		}
	}
	c.HTML(http.StatusOK, "login.tmpl", gin.H{
		"title":    "SSO | Login",
		"is_gamer": is_gamer,
		"is_game":  is_game,
		"is_guild": is_guild,
		"lng":      lng,
	})
}

// @Summary SignupHandler
// @ID SignupHandler
// @Produce multipart/form-data
// @Security JwtHeader
// @Success 200 {string} text/html
// @Param state formData string false "state"
// @Param username formData string false "username"
// @Param password formData string false "password"
// @Param confirm formData string false "confirm"
// @Router /signup [get]
// @Router /signup [post]
func SignupHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("signup recovered from panic %s", r)
		}
	}()

	r := c.Request

	ginStore := ginSession.Default(c)

	// i18n
	lng := c.DefaultQuery("lang", "en")

	// get oauth server from ctx
	srvCtx := c.MustGet("oauthServer")
	srv := srvCtx.(*server.Server)
	if srv == nil {
		err := fmt.Errorf("oauth server invalid")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ssoURLCtx := c.MustGet("ssoURL")
	ssoURL := ssoURLCtx.(string)
	if len(ssoURL) == 0 {
		err := fmt.Errorf("ssoURL is empty")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// get client id from session, otherwise using demo client
	var clientId, clientSecret, clientRedirectURL, codeChallenge string
	var form url.Values

	v := ginStore.Get(RETURN_URI_KEY)
	if v != nil {
		helper.GetLogger().Debug("get return uri from session success %T", v)
		form = v.(url.Values)

		if clientIds, ok := form["client_id"]; ok {
			clientId = clientIds[0]
			var client models.Client
			if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
				helper.GetLogger().Error("get client from db failed with error %s, eg. client demo", err)
			} else {
				helper.GetLogger().Debug("found client in db with id %d", client.ID)
				clientSecret = client.ClientSecret
				if redirectURI, ok := form["redirect_uri"]; ok {
					helper.GetLogger().Debug("found redirect uri from session %s", redirectURI)
					clientRedirectURL = redirectURI[0]
				} else {
					helper.GetLogger().Debug("read redirect uri from db")
					clientRedirectURL = client.RedirectUrl
				}

				if codeChal, ok := form["code_challenge"]; ok {
					codeChallenge = codeChal[0]
				}
			}
		}
	}
	if len(clientId) > 0 && len(clientSecret) > 0 && len(clientRedirectURL) > 0 && len(codeChallenge) > 0 {
		helper.GetLogger().Debug("found client info %s in session", clientId)
		helper.GetLogger().Debug("client id %s redirect uri %s code challenge %s", clientId, clientRedirectURL, codeChallenge)
	} else {
		helper.GetLogger().Debug("client info non-existence in session, using demo client")
		clientIdCtx := c.MustGet("clientId")
		clientId = clientIdCtx.(string)
		if len(clientId) == 0 {
			err := fmt.Errorf("not found client id in context")
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		clientSecretCtx := c.MustGet("clientSecret")
		clientSecret = clientSecretCtx.(string)
		if len(clientSecret) == 0 {
			err := fmt.Errorf("not found client secret in context")
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		clientRedirectURLCtx := c.MustGet("clientRedirectURL")
		clientRedirectURL = clientRedirectURLCtx.(string)
		if len(clientSecret) == 0 {
			err := fmt.Errorf("not found client secret in context")
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		codeChallengeCtx := c.MustGet("codeChallenge")
		codeChallengeStr := codeChallengeCtx.(string)
		codeChallenge = helper.GenCodeChallengeS256(codeChallengeStr)

		helper.GetLogger().Debug("codechallenge %s digest %s", codeChallengeStr, codeChallenge)
	}

	helper.GetLogger().Debug("client id %s secret %s redirect url %s", clientId, clientSecret, clientRedirectURL)

	state, exists := c.GetQuery("state")
	if exists && state == "verify_email" {
		// validate token sent along with url
		token, err := srv.ValidationBearerToken(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
			return
		}

		dareidStr := token.GetUserID()
		dareid, err := strconv.ParseInt(dareidStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "parsing dareid failed"})
			return
		}
		helper.GetLogger().Debug("found dareid %d from access token", dareid)

		var account models.Account
		if err := models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not found dareid"})
			return
		}

		if err := models.GetAccountRepository().VerifyEmail(&account); err != nil {
			helper.GetLogger().Error("verify email failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// save dareid into session and redirect to authorization page
		ginStore.Set(LOGGED_UID_KEY, fmt.Sprintf("%d", account.Dareid))
		ginStore.Save()

		// save redirect info from url into session
		if r.Form == nil {
			r.ParseForm()
		}

		ginStore.Set(RETURN_URI_KEY, r.Form)
		ginStore.Save()

		c.HTML(http.StatusOK, "signup.tmpl", gin.H{
			"title":        "SSO | Signup",
			"email_verify": 2, // completed
			"email":        *account.Email,
			"lng":          lng,
		})
		return
	}

	if r.Method == "POST" {
		if r.Form == nil {
			helper.GetLogger().Debug("submitted form is nil")
			if err := r.ParseForm(); err != nil {
				helper.GetLogger().Debug("parsing form failed with error %s", err)
				c.JSON(http.StatusNotAcceptable, gin.H{"error": err.Error()})
				return
			}
		}

		email := r.Form.Get("username")
		password := r.Form.Get("password")
		confirm := r.Form.Get("confirm")

		if !helper.EmailValid(email) {
			err := fmt.Errorf("email invalid")
			helper.GetLogger().Error("email %s invalid", email)
			c.HTML(http.StatusNotAcceptable, "signup.tmpl", gin.H{
				"title": "SSO | Signup",
				"error": err.Error(),
				"email": email,
				"lng":   lng,
			})
			return
		}

		if password != confirm {
			helper.GetLogger().Error("password and confirm mistmatched")
			err := fmt.Errorf("password not match")
			c.HTML(http.StatusNotAcceptable, "signup.tmpl", gin.H{
				"title":          "SSO | Signup",
				"error_password": err.Error(),
				"email":          email,
				"lng":            lng,
			})
			return
		}

		if len(password) < PASSWORD_LENGTH_MINIMUM {
			err := fmt.Errorf("password is too short")
			helper.GetLogger().Error("password %s is too short", password)
			c.HTML(http.StatusNotAcceptable, "signup.tmpl", gin.H{
				"title": "SSO | Signup",
				"error": err.Error(),
				"email": email,
				"lng":   lng,
			})
			return
		}

		account := core.AccountCore{
			Email:    email,
			Password: password,
		}

		accountId, err := models.GetAccountRepository().CreateUser(account)
		if err != nil {
			helper.GetLogger().Error("create user failed with error %s", err)
			data := gin.H{
				"title": "SSO | Signup",
				"error": err.Error(),
				"email": email,
				"lng":   lng,
			}
			if accountId > 0 {
				data["account_id"] = accountId
			}

			c.HTML(http.StatusNotAcceptable, "signup.tmpl", data)
			return
		}
		helper.GetLogger().Debug("create user succeed with id %d", accountId)

		if accountId > 0 {
			var acct models.Account
			if err := models.DB.Where("id = ?", accountId).First(&acct).Error; err != nil {
				helper.GetLogger().Error("not found existed user with id %d", accountId)
				err := fmt.Errorf("user not found")
				c.HTML(http.StatusInternalServerError, "signup.tmpl", gin.H{
					"title": "SSO | Signup",
					"error": err.Error(),
					"email": email,
					"lng":   lng,
				})
				return
			}

			result, err := SendEmailVerification(srv, ssoURL, clientId, clientSecret, clientRedirectURL, codeChallenge, acct)
			if err != nil {
				helper.GetLogger().Error("send email verification failed with error %s", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			helper.GetLogger().Debug("send mail verification success with status %d", result.StatusCode)

			c.HTML(http.StatusOK, "signup.tmpl", gin.H{
				"title":        "SSO | Signup",
				"email_verify": 1, // request
				"email":        *acct.Email,
				"lng":          lng,
			})
			return
		} else {
			err = fmt.Errorf("not found user")
			c.HTML(http.StatusInternalServerError, "signup.tmpl", gin.H{
				"title": "SSO | Signup",
				"error": err.Error(),
				"email": email,
				"lng":   lng,
			})
			return
		}
	}
	c.HTML(http.StatusOK, "signup.tmpl", gin.H{
		"title": "SSO | Signup",
		"lng":   lng,
	})
}

// @Summary AuthHandler
// @ID AuthHandler
// @Produce multipart/form-data
// @Success 200 {string} text/html
// @Router /auth [get]
// @Router /auth [post]
func AuthHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("auth recovered from error %s", r)
		}
	}()

	// i18n
	lng := c.DefaultQuery("lang", "en")

	ginStore := ginSession.Default(c)

	dareid := ginStore.Get(LOGGED_UID_KEY)
	if dareid == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	dareid = dareid.(string)

	clientName := "DareApps"
	var form url.Values

	// specify client identity from URI
	v := ginStore.Get(RETURN_URI_KEY)
	if v != nil {
		helper.GetLogger().Debug("get return uri from session success %T", v)
		form = v.(url.Values)
		if clientIds, ok := form["client_id"]; ok {
			clientId := clientIds[0]
			var client models.Client
			if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
				helper.GetLogger().Error("get client from db failed with error %s, eg. client demo", err)
			} else {
				helper.GetLogger().Debug("found client in db with id %d", client.ID)
				clientName = client.Name
			}
		}
	}

	// check if onetime token exists
	cookieDomain := "localhost" // default
	cookieTTL := 365 * 24 * 3600

	cookieDomainCtx, exists := c.Get("cookieDomain")
	if exists {
		cookieDomain = cookieDomainCtx.(string)
	}
	token, err := c.Cookie(OAUTH_AUTH_COOKIE_NAME)
	if len(token) > 0 && err == nil {
		helper.GetLogger().Debug("found oauth-auth cookie token %s", token)
		claims, err := helper.GetJwtHelper().ParseCustomToken(token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if claims.DareID != dareid.(string) {
			helper.GetLogger().Error("oauth-auth token dareid not matched, clean cookie")
			c.SetCookie(OAUTH_AUTH_COOKIE_NAME, "", -1, "/", cookieDomain, false, false)
		} else {
			helper.GetLogger().Debug("verify oauth token success with dareid %s", claims.DareID)
			c.Redirect(http.StatusFound, "/oauth/authorize")
			return
		}
	}

	if c.Request.Method == http.MethodPost {
		// authorization submitted, create onetime token
		token, err := helper.GetJwtHelper().CreateCustomToken(dareid.(string), "oauth_auth", AUTH_COOKIE_TTL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		helper.GetLogger().Debug("create jwt token success %s", token)
		c.SetCookie(OAUTH_AUTH_COOKIE_NAME, token, cookieTTL, "/", cookieDomain, false, false)
		//c.Redirect(http.StatusFound, "/oauth/authorize")
		c.HTML(http.StatusOK, "auth.tmpl", gin.H{
			"title":        "SSO | Authorize",
			"client":       clientName,
			"authorized":   1,
			"redirect_url": "/oauth/authorize",
			"lng":          lng,
		})
		return
	}

	c.HTML(http.StatusOK, "auth.tmpl", gin.H{
		"title":        "SSO | Authorize",
		"client":       clientName,
		"authorized":   0,
		"redirect_url": "/oauth/authorize",
		"lng":          lng,
	})
}

// @Summary RecoverPassword
// @ID RecoverPassword
// @Produce multipart/form-data
// @Param email formData string true "email"
// @Success 200 {string} text/html
// @Router /recover_password [post]
func RecoverPassword(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("recover-passwd recovered from error %s", r)
		}
	}()

	// fetch client id and secret from context
	clientIdCtx, existed := c.Get("clientId")
	if !existed {
		err := fmt.Errorf("not found client id in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	clientId := clientIdCtx.(string)
	if len(clientId) == 0 {
		err := fmt.Errorf("not found client id in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	clientSecretCtx, existed := c.Get("clientSecret")
	if !existed {
		err := fmt.Errorf("not found client secret in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	clientSecret := clientSecretCtx.(string)
	if len(clientSecret) == 0 {
		err := fmt.Errorf("not found client secret in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	ssoURLCtx, existed := c.Get("ssoURL")
	if !existed {
		err := fmt.Errorf("not found sso endpoint in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	ssoURL := ssoURLCtx.(string)
	if len(ssoURL) == 0 {
		err := fmt.Errorf("not found sso endpoint in context")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
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
		err := fmt.Errorf("invalid type oauth server")
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	r := c.Request

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

		email := r.Form.Get("email")

		if !helper.EmailValid(email) {
			err := fmt.Errorf("email invalid")
			c.JSON(http.StatusNotFound, gin.H{"code": -2, "error": err.Error()})
			return
		}

		var account models.Account
		if err := models.GetAccountRepository().GetAccountByEmail(email, &account); err != nil {
			err := fmt.Errorf("this email hasn't signed up yet, do you want to register")
			c.JSON(http.StatusNotFound, gin.H{"code": -1, "error": err.Error()})
			return
		}

		// oauth2 token
		gt := oauth2.GrantType("password")
		tgr := &oauth2.TokenGenerateRequest{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Request:      c.Request,
			Scope:        "reset_password",
			UserID:       fmt.Sprintf("%d", account.Dareid),
		}
		ti, err := srv.GetAccessToken(c.Request.Context(), gt, tgr)
		if err != nil {
			helper.GetLogger().Error("get oauth token failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		helper.GetLogger().Debug("generate access token %s for dareid %d", ti.GetAccess(), account.Dareid)

		result, err := service.GetSendgridService().SendRecoverPasswordEmail(email, ssoURL, ti.GetAccess())
		if err != nil {
			helper.GetLogger().Error("send ses mail failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		helper.GetLogger().Debug("send ses mail success with status %d", result.StatusCode)
		c.JSON(http.StatusOK, gin.H{"code": 0, "message": fmt.Sprintf("We have sent you an email to %s so that you can change your password.", email)})
		return
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "support POST method only"})
		return
	}
}

// @Summary ChangePassword
// @ID ChangePassword
// @Produce multipart/form-data
// @Security JwtHeader
// @Param password formData string false "password"
// @Param confirm formData string false "confirm"
// @Success 200 {string} text/html
// @Router /change_password [get]
// @Router /change_password [post]
func ChangePassword(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("change-passwd recovered from error %s", r)
		}
	}()

	// i18n
	lng := c.DefaultQuery("lang", "en")

	// get oauth server from ctx
	srvCtx, existed := c.Get("oauthServer")
	//state := "all"

	if !existed {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	srv := srvCtx.(*server.Server)
	if srv == nil {
		err := fmt.Errorf("oauth server invalid")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// validate token sent along with url
	token, err := srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": -1, "error": "invalid access token"})
		return
	}

	dareidStr := token.GetUserID()
	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": -2, "error": "parsing dareid failed"})
		return
	}
	helper.GetLogger().Debug("found dareid %d from access token", dareid)

	var account models.Account
	if err := models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": -3, "error": "not found dareid"})
		return
	}

	r := c.Request
	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

		password := r.Form.Get("password")
		confirm := r.Form.Get("confirm")

		if password != confirm {
			helper.GetLogger().Debug("password and confirm mistmatched")
			err := fmt.Errorf("password not match")
			c.HTML(http.StatusOK, "change_password.tmpl", gin.H{
				"title":          "SSO | Signup",
				"error_password": err.Error(),
				"lng":            lng,
			})
			return
		}

		if len(password) < PASSWORD_LENGTH_MINIMUM {
			helper.GetLogger().Debug("password is too short")
			err := fmt.Errorf("password is too short")
			c.HTML(http.StatusOK, "change_password.tmpl", gin.H{
				"title":          "SSO | Signup",
				"error_password": err.Error(),
				"lng":            lng,
			})
			return
		}

		if err := models.GetAccountRepository().ChangePassword(password, &account); err != nil {
			helper.GetLogger().Debug("update password failed with error %s for dareid %d", err, dareid)
			c.HTML(http.StatusOK, "change_password.tmpl", gin.H{
				"title": "SSO | Signup",
				"error": err.Error(),
				"lng":   lng,
			})
			return
		} else {
			helper.GetLogger().Debug("update password success for dareid %d", dareid)
			c.HTML(http.StatusOK, "change_password.tmpl", gin.H{
				"title":           "SSO | Signup",
				"success":         "Password updated success.",
				"change_password": 1,
				"lng":             lng,
			})
			return
		}
	} else {
		c.HTML(http.StatusOK, "change_password.tmpl", gin.H{
			"title":        "SSO | Change password",
			"access_token": token.GetAccess(),
			"lng":          lng,
		})
	}
}

func VerifyEmail(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("verify-email recovered from error %s", r)
		}
	}()

	// get oauth server from ctx
	srvCtx, existed := c.Get("oauthServer")
	//state := "all"

	if !existed {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	srv := srvCtx.(*server.Server)
	if srv == nil {
		err := fmt.Errorf("oauth server invalid")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// validate token sent along with url
	token, err := srv.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": -1, "error": "invalid access token"})
		return
	}

	dareidStr := token.GetUserID()
	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": -2, "error": "parsing dareid failed"})
		return
	}
	helper.GetLogger().Debug("found dareid %d from access token", dareid)

	var account models.Account
	if err := models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": -3, "error": "not found dareid"})
		return
	}

	isVerified := int32(1)
	account.EmailVerified = &isVerified
	account.UpdatedAt = time.Now()

	if err := models.DB.Save(account).Error; err != nil {
		helper.GetLogger().Error("verify email failed with error %s", err)
		c.JSON(http.StatusUnauthorized, gin.H{"code": -4, "error": "verify email failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "verify success"})
}

type GenerateChallengeReq struct {
	Wallet  string `json:"wallet" binding:"required"`
	ChainId string `json:"chain_id"`
}

type GenerateChallengeResp struct {
	SuccessResp
	Challenge string `json:"challenge"`
	Hash      string `json:"hash"`
}

// @Summary Generate wallet challenge
// @ID GenerateChallenge
// @Produce application/json
// @Param _ body GenerateChallengeReq true "json body"
// @Success 201 {object} GenerateChallengeResp
// @Failure 400 {object} BadRequestResp
// @Failure 500 {object} ServerErrorResp
// @Router /generate-challenge [post]
func GenerateChallenge(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("generate-challenge recovered from error %s", r)
		}
	}()

	var req GenerateChallengeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.GetLogger().Error("parsing req body failed with error %s", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if valid := helper.IsValidWalletAddress(req.Wallet); !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("wallet address invalid").Error()})
		return
	}

	address := strings.ToLower(req.Wallet)

	// Generate a random nonce to include in our challenge
	nonceBytes := make([]byte, 32)
	n, err := rand.Read(nonceBytes)
	if n != 32 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("nonce: n != 64 (bytes)")})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	nonce := hex.EncodeToString(nonceBytes)

	message := fmt.Sprintf(`
Click to sign in. No password needed!
This request will not trigger a blockchain transaction or cost any gas fees.

Wallet address: %s	
Nonce: %s`, address, nonce)

	hash := helper.HashSignedMessage(message)

	helper.GetLogger().Debug("nonce %s challenge hash %s", nonce, hash)
	if _, err := models.GetAccountRepository().CreateChallenge(address, nonce, hash, req.ChainId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"code": 0, "message": "challenge created success", "challenge": message, "hash": hash})
}

type VerifyChallengeReq struct {
	Signature string `json:"signature" binding:"required"`
	Hash      string `json:"hash" binding:"required"`
	Scope     string `json:"scope"`
}

type VerifyChallengeResp struct {
	SuccessResp
	Account core.AccountDare  `json:"account"`
	Oauth   map[string]string `json:"oauth"`
}

// @Summary Verify challenge signature
// @ID VerifyChallenge
// @Security ClientBasicAuth
// @Produce application/json
// @Param _ body VerifyChallengeReq true "json body"
// @Success 200 {object} VerifyChallengeResp
// @Failure 400 {object} BadRequestResp
// @Failure 500 {object} ServerErrorResp
// @Router /verify-challenge [post]
func VerifyChallenge(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("verify-challenge recovered from error %s", r)
		}
	}()

	// get oauth server from ctx
	srvCtx, existed := c.Get("oauthServer")

	if !existed {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("not found oauth server in context").Error()})
		return
	}

	srv := srvCtx.(*server.Server)
	if srv == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("not found oauth server in context").Error()})
		return
	}

	var req VerifyChallengeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		helper.GetLogger().Error("parsing req body failed with error %s", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	challenge, err := VerifyWalletChallenge(req.Hash, req.Signature)
	if err != nil {
		helper.GetLogger().Error("verify challenge error %s", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Errorf("verify challenge error %s", err).Error()})
		return
	}

	// check whether wallet is associated with account yet
	account := models.Account{}
	if err := models.GetAccountRepository().GetAccountByWallet(challenge.Wallet, &account); err != nil {
		helper.GetLogger().Debug("account is not existed by wallet %s, create new", challenge.Wallet)
		newAccount, err := models.GetAccountRepository().CreateUserWithWalletAddress(challenge.Wallet)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("create account error %s", err).Error()})
			return
		}
		if err := models.GetAccountRepository().GetAccountByID(newAccount.ID, &account); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("create account error %s", err).Error()})
			return
		}
	}
	helper.GetLogger().Debug("found account with dareid %d", account.Dareid)
	// hotfix: need to create return object to prevent int64 casting error of dareid
	accountDare := core.AccountDare{
		Dareid: fmt.Sprintf("%d", account.Dareid),
	}
	if account.WalletAddress != nil {
		accountDare.WalletAddress = *account.WalletAddress
	}
	if account.Email != nil {
		accountDare.Email = *account.Email
	}

	// oauth2 token
	clientId := c.MustGet(gin.AuthUserKey).(string)
	var clientSecret string

	demoClientId := c.MustGet("demoClientId").(string)
	demoClientSecret := c.MustGet("demoClientSecret").(string)
	if clientId == demoClientId {
		clientSecret = demoClientSecret
	} else {
		var client models.Client
		if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Errorf("not found client %s", clientId).Error()})
			return
		}
		clientSecret = client.ClientSecret
	}

	helper.GetLogger().Debug("found client id %s and secret %s", clientId, clientSecret)
	scope := "all" // default
	if len(req.Scope) > 0 {
		scope = req.Scope
	}

	gt := oauth2.GrantType("password")
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Request:      c.Request,
		Scope:        scope,
		UserID:       fmt.Sprintf("%d", account.Dareid),
	}
	ti, err := srv.GetAccessToken(c.Request.Context(), gt, tgr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("generate token error %s", err).Error()})
		return
	}

	// invalidate challenge
	if err := models.GetAccountRepository().InvalidateChallenge(challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("invalidate challenge error %s", err).Error()})
		return
	}

	// returns account with oauth token
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "verify success", "account": accountDare, "oauth": srv.GetTokenData(ti)})
}

func VerifyWalletChallenge(hashStr string, signatureStr string) (*models.Challenge, error) {
	// verify if nonce is used
	challenge := models.Challenge{}
	if err := models.GetAccountRepository().GetChallengeByHash(hashStr, &challenge); err != nil {
		return nil, err
	}

	helper.GetLogger().Debug("found challenge %s", challenge.Hash)
	if err := models.GetAccountRepository().ValidateNonce(&challenge, false); err != nil {
		return nil, err
	}

	helper.GetLogger().Debug("nonce is valid %s", challenge.Hash)

	// hex-decoded hash
	hash, err := hexutil.Decode(hashStr)
	if err != nil {
		return nil, err
	}

	// hex-decoded signature
	signature, err := hexutil.Decode(signatureStr)
	if err != nil {
		return nil, err
	}

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] -= 27

	// get the pubkey used to sign this signature
	signer := challenge.Wallet

	// EOA ecrecover then EIP1271 signature
	if err := helper.VerifySignedMessage(hash, signature, signer); err != nil {
		helper.GetLogger().Debug("EOA verification failed %s", err.Error())

		chainId := os.Getenv("DEFAULT_CHAIN_ID")
		if len(challenge.ChainId) > 0 {
			chainId = challenge.ChainId
		}

		chainConfig := models.ChainConfig{}
		if err := models.GetAccountRepository().GetChainConfig(chainId, &chainConfig); err != nil {
			return nil, err
		}

		if err := helper.VerifyEIP1271SignedMessage(hashStr, signatureStr, signer, chainConfig.Rpc); err != nil {
			return nil, err
		}
	}

	return &challenge, nil
}
