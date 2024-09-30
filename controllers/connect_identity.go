package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sso/helper"
	"sso/models"
	"sso/service"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
)

const (
	GOOGLE_PROVIDER = "google"

	CONNECT_REDIRECT_URL_SESSION_KEY = "ConnectProviderRedirectURL"
	CONNECT_SESSION_NAME             = "sso-oauth-connect"

	UID_COOKIE_NAME          = "connect_provider_uid"
	CLIENTID_COOKIE_NAME     = "connect_provider_clientid"
	REDIRECT_URL_COOKIE_NAME = "connect_provider_redirect_url"
	CONNECT_COOKIE_TTL       = 300
)

// @Summary ConnectIdentityProvider
// @ID ConnectIdentityProvider
// @Produce application/json
// @Security JwtHeader
// @Param provider path string true "provider"
// @Success 200 {string} application/json
// @Router /connect/:provider [get]
func ConnectIdentityProvider(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("connect-identity recovered from panic %s", r)
		}
	}()

	// get oauth server from ctx
	srvCtx, existed := c.Get("oauthServer")
	isDemo := false
	state := "all"

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

	dareid := token.GetUserID()
	clientId := token.GetClientID()

	clientDemoIdInf, exists := c.Get("clientDemoId")
	if exists {
		switch demoId := clientDemoIdInf.(type) {
		case string:
			if demoId == clientId {
				isDemo = true
			}
		}
	}

	if !isDemo {
		var client models.Client
		if err := models.GetClientRepository().GetClientByClientId(clientId, &client); err != nil {
			err2 := fmt.Errorf("not found client")
			helper.GetLogger().Error("not found client %s", clientId)
			c.JSON(http.StatusNotFound, gin.H{"error": err2.Error()})
			return
		}
		state = fmt.Sprintf("client_%d_dareid_%s", client.ID, dareid)
	} else {
		state = fmt.Sprintf("client_0_dareid_%s", dareid)
	}

	botName := "sso_bot" // default
	botNameCtx, exists := c.Get("botName")
	if exists {
		botName = botNameCtx.(string)
		helper.GetLogger().Debug("read bot name %s from context", botName)
	}

	// save connect provider data into cookie, for keeping state cross request
	cookieDomain := "localhost" // default
	cookieTTL := 300

	cookieDomainCtx, exists := c.Get("cookieDomain")
	if exists {
		cookieDomain = cookieDomainCtx.(string)
	}
	cookieTTLCtx, exists := c.Get("cookieTTL")
	if exists {
		cookieTTL = cookieTTLCtx.(int)
	}

	provider := c.Param("provider")
	var authorizedUrl string
	switch provider {
	case GOOGLE_PROVIDER:
		authorizedUrl = "/authorized/google?state=" + state
	default:
		helper.GetLogger().Error("invalid provider %s", provider)
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "error": fmt.Sprintf("invalid provider %s", provider)})
		return
	}

	// save connect data into cookie
	c.SetCookie(UID_COOKIE_NAME, dareid, cookieTTL, "/", cookieDomain, false, false)
	c.SetCookie(CLIENTID_COOKIE_NAME, clientId, cookieTTL, "/", cookieDomain, false, false)

	// fetch redirect url from query
	redirectURL := c.Request.FormValue("redirect_url")
	if len(redirectURL) > 0 {
		helper.GetLogger().Debug("found redirect url %s in query, save to cookie", redirectURL)
		c.SetCookie(REDIRECT_URL_COOKIE_NAME, redirectURL, cookieTTL, "/", cookieDomain, false, false)
	}

	c.HTML(http.StatusOK, "loading.tmpl", gin.H{
		"title":          "SSO | Provider Authorized",
		"provider":       provider,
		"authorized_url": authorizedUrl,
		"bot_name":       botName,
	})
}

// @Summary GoogleAuthorizedReq
// @ID GoogleAuthorizedReq
// @Produce application/json
// @Param state query string true "state"
// @Param redirect_url query string false "redirect_url"
// @Success 200 {string} application/json
// @Router /authorized/google [get]
func GoogleAuthorizedReq(c *gin.Context) {
	redirectURL := c.Request.FormValue("redirect_url")
	if len(redirectURL) > 0 {
		cookieDomain := "localhost" // default
		cookieTTL := 300

		cookieDomainCtx, exists := c.Get("cookieDomain")
		if exists {
			cookieDomain = cookieDomainCtx.(string)
		}
		cookieTTLCtx, exists := c.Get("cookieTTL")
		if exists {
			cookieTTL = cookieTTLCtx.(int)
		}

		helper.GetLogger().Debug("found redirect url %s in query, save to cookie", redirectURL)
		c.SetCookie(REDIRECT_URL_COOKIE_NAME, redirectURL, cookieTTL, "/", cookieDomain, false, false)
	}

	state := c.Request.FormValue("state")
	authURL := service.GetGoogleOauth().GetAuthorizeURLWithState(state)
	helper.GetLogger().Debug("generated Auth URL %s", authURL)
	c.Redirect(http.StatusFound, authURL)
}

// @Summary GoogleOauthHandler
// @ID GoogleOauthHandler
// @Produce application/json
// @Param state query string true "state"
// @Param code query string true "code"
// @Success 200 {string} application/json
// @Router /authorized/google_handler [get]
func GoogleOauthHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("google recovered from panic %s", r)
		}
	}()

	srvCtx := c.MustGet("oauthServer")
	srv := srvCtx.(*server.Server)

	if srv == nil {
		err := fmt.Errorf("not found oauth server in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// fetching data from cookie
	redirectURL, err := c.Cookie(REDIRECT_URL_COOKIE_NAME)
	if err != nil {
		helper.GetLogger().Error("fetching redirect url from cookie failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fetching redirect url failed"})
		return
	} else if len(redirectURL) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fetching redirect url empty"})
		return
	}
	helper.GetLogger().Debug("found redirect url %s in cookie", redirectURL)

	state := c.Request.FormValue("state")
	code := c.Request.FormValue("code")
	helper.GetLogger().Debug("google redirect with state %s and code %s", state, code)

	if len(code) == 0 {
		helper.GetLogger().Error("code empty")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("code not found")})
		return
	}

	if err := service.GetGoogleOauth().Exchange(code); err != nil {
		helper.GetLogger().Error("exchange code failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	googleUserInfo, err := service.GetGoogleOauth().FetchUserProfile()
	if err != nil {
		helper.GetLogger().Error("fetching user info failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var account models.Account
	if err := models.GetAccountRepository().GetAccountByEmail(googleUserInfo.Email, &account); err != nil {
		// create new account
		account, err = models.GetAccountRepository().CreateUserByGoogle(*googleUserInfo)
		if err != nil {
			helper.GetLogger().Error("create account failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "message": "create account failed", "error": err.Error()})
			return
		}
	}

	emailVerified := int32(0)
	if googleUserInfo.EmailVerified {
		emailVerified = int32(1)
	}

	var accountGoogle models.AccountGoogle
	if err := models.DB.Where("account_id=?", account.ID).First(&accountGoogle).Error; err != nil {
		// create new google
		helper.GetLogger().Debug("not found account google info for account %d, create new...", account.ID)

		accountGoogle = models.AccountGoogle{
			AccountID:     account.ID,
			Dareid:        account.Dareid,
			Sub:           googleUserInfo.Sub,
			Name:          googleUserInfo.Name,
			GivenName:     googleUserInfo.GivenName,
			FamilyName:    googleUserInfo.FamilyName,
			Profile:       googleUserInfo.Profile,
			Picture:       googleUserInfo.Picture,
			Email:         googleUserInfo.Email,
			EmailVerified: &emailVerified,
		}

		if err := models.DB.Create(&accountGoogle).Error; err != nil {
			helper.GetLogger().Error("create account google info failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "message": "create account google info failed", "error": err.Error()})
			return
		}
	} else {
		// update
		helper.GetLogger().Debug("found existed account google info for account %d, update...", account.ID)

		accountGoogle.Sub = googleUserInfo.Sub
		accountGoogle.Name = googleUserInfo.Name
		accountGoogle.GivenName = googleUserInfo.GivenName
		accountGoogle.FamilyName = googleUserInfo.FamilyName
		accountGoogle.Profile = googleUserInfo.Profile
		accountGoogle.Picture = googleUserInfo.Picture
		accountGoogle.Email = googleUserInfo.Email
		accountGoogle.EmailVerified = &emailVerified
		accountGoogle.UpdatedAt = time.Now()

		if err := models.DB.Save(&accountGoogle).Error; err != nil {
			helper.GetLogger().Error("update account google info failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "message": "update account google info failed", "error": err.Error()})
			return
		}
	}

	s := strings.Split(state, "_") // state_clientID_codeChallenge_codeChallengeMethod
	if len(s) < 4 {
		helper.GetLogger().Error("invalid state")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("invalid state")})
		return
	}

	clientIdStr := s[1]
	codeChallenge := s[2]
	codeChallengeMethod := s[3]
	r := c.Request

	ti, err := srv.GetAuthorizeToken(r.Context(), &server.AuthorizeRequest{
		ResponseType:        oauth2.ResponseType("code"),
		ClientID:            clientIdStr,
		RedirectURI:         redirectURL,
		UserID:              strconv.FormatInt(account.Dareid, 10),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: oauth2.CodeChallengeMethod(codeChallengeMethod),
		Request:             r,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	url := fmt.Sprintf("%s?status=connected&code=%s&state=%s", redirectURL, ti.GetCode(), state)
	helper.GetLogger().Debug("redirect to client profile by url %s", url)
	c.Redirect(http.StatusFound, url)
}

// @Summary GoogleConnectHandler
// @ID GoogleConnectHandler
// @Produce application/json
// @Param state formData string true "state"
// @Param code formData string true "code"
// @Success 200 {string} application/json
// @Router /connect/google_handler [get]
func GoogleConnectHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			helper.GetLogger().Error("google recovered from panic %s", r)
		}
	}()

	// fetching data from cookie
	redirectURL, err := c.Cookie(REDIRECT_URL_COOKIE_NAME)
	if err != nil {
		helper.GetLogger().Error("fetching redirect url from cookie failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fetching redirect url failed"})
		return
	} else {
		helper.GetLogger().Debug("found redirect url %s in cookie", redirectURL)
	}

	state := c.Request.FormValue("state")
	code := c.Request.FormValue("code")
	helper.GetLogger().Debug("google redirect with state %s and code %s", state, code)

	if len(code) == 0 {
		helper.GetLogger().Error("code empty")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("code not found")})
		return
	}

	s := strings.Split(state, "_")
	if len(s) < 4 {
		helper.GetLogger().Error("invalid state")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("invalid state")})
		return
	}

	isDemo := false
	clientIdStr := s[1]
	dareidStr := s[3]

	if clientIdStr == "0" { // client demo
		isDemo = true
	}
	helper.GetLogger().Debug("isdemo %t", isDemo)

	dareid, err := strconv.ParseInt(dareidStr, 10, 64)
	if err != nil {
		helper.GetLogger().Error("invalid dareid in state")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("invalid dareid in state")})
		return
	}

	var account models.Account
	if err := models.GetAccountRepository().GetAccountByDareid(dareid, &account); err != nil {
		helper.GetLogger().Error("not found dareid %s", dareid)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	clientId, err := strconv.ParseInt(clientIdStr, 10, 64)
	if !isDemo {
		if err != nil {
			helper.GetLogger().Error("invalid client in state")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Errorf("invalid client in state")})
			return
		}
	}

	var client models.Client
	if !isDemo {
		if err := models.DB.Where("id=?", clientId).First(&client).Error; err != nil {
			helper.GetLogger().Error("not found client %s", clientId)
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
	}

	if err := service.GetGoogleOauth().Exchange(code); err != nil {
		helper.GetLogger().Error("exchange code failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	googleUserInfo, err := service.GetGoogleOauth().FetchUserProfile()
	if err != nil {
		helper.GetLogger().Error("fetching user info failed with error %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	emailVerified := int32(0)
	if googleUserInfo.EmailVerified {
		emailVerified = int32(1)
	}
	var accountGoogle models.AccountGoogle
	if err := models.DB.Where("account_id=?", account.ID).First(&accountGoogle).Error; err != nil {
		// create
		helper.GetLogger().Debug("not found account google info for account %d, create new...", account.ID)

		accountGoogle = models.AccountGoogle{
			AccountID:     account.ID,
			Dareid:        account.Dareid,
			Sub:           googleUserInfo.Sub,
			Name:          googleUserInfo.Name,
			GivenName:     googleUserInfo.GivenName,
			FamilyName:    googleUserInfo.FamilyName,
			Profile:       googleUserInfo.Profile,
			Picture:       googleUserInfo.Picture,
			Email:         googleUserInfo.Email,
			EmailVerified: &emailVerified,
			// CreatedAt:     time.Now(),
			// UpdatedAt:     time.Now(),
			// IsDeleted:     0,
		}

		if err := models.DB.Create(&accountGoogle).Error; err != nil {
			helper.GetLogger().Error("create account google info failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "message": "create account google info failed", "error": err.Error()})
			return
		}
	} else {
		// update
		helper.GetLogger().Debug("found existed account google info for account %d, update...", account.ID)

		accountGoogle.Sub = googleUserInfo.Sub
		accountGoogle.Name = googleUserInfo.Name
		accountGoogle.GivenName = googleUserInfo.GivenName
		accountGoogle.FamilyName = googleUserInfo.FamilyName
		accountGoogle.Profile = googleUserInfo.Profile
		accountGoogle.Picture = googleUserInfo.Picture
		accountGoogle.Email = googleUserInfo.Email
		accountGoogle.EmailVerified = &emailVerified
		accountGoogle.UpdatedAt = time.Now()

		if err := models.DB.Save(&accountGoogle).Error; err != nil {
			helper.GetLogger().Error("update account google info failed with error %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "message": "update account google info failed", "error": err.Error()})
			return
		}
	}

	// redirect back to client page
	if len(redirectURL) > 0 {
		helper.GetLogger().Debug("found redirect url in session %s", redirectURL)
		url := fmt.Sprintf("%s?connect=google&gmail=%s", redirectURL, googleUserInfo.Email)
		helper.GetLogger().Debug("redirect to client profile by url %s", url)
		c.Redirect(http.StatusFound, url)
		return
	} else {
		helper.GetLogger().Debug("not found redirect url in session, get from DB")
		if len(client.RedirectUrl) > 0 {
			url := fmt.Sprintf("%s?connect=google&gmail=%s", client.RedirectUrl, googleUserInfo.Email)
			helper.GetLogger().Debug("redirect to client profile by url %s", url)
			c.Redirect(http.StatusFound, url)
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "connect google success", "google": accountGoogle})
}
