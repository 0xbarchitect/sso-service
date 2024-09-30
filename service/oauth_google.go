package service

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"sso/core"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	_googleOauthIns OAuthGoogleInf
)

func GetGoogleOauth() OAuthGoogleInf {
	mu.Lock()
	defer mu.Unlock()
	return _googleOauthIns
}

func SetGoogleOauth(ins OAuthGoogleInf) {
	mu.Lock()
	defer mu.Unlock()
	_googleOauthIns = ins
}

func NewOAuthGoogle(clientId string, clientSecret string, redirectURL string) (*OAuthGoogle, error) {
	svc := &OAuthGoogle{ClientID: clientId, ClientSecret: clientSecret, RedirectURL: redirectURL}
	err := svc.Init()
	return svc, err
}

type OAuthGoogleInf interface {
	Init() error
	GetAuthorizeURLWithState(state string) string
	Exchange(code string) error
	FetchUserProfile() (*core.GoogleUserInfo, error)
}

type OAuthGoogle struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	CookieDomain string

	Config *oauth2.Config
	Client *http.Client
	Ctx    context.Context
}

func (g *OAuthGoogle) Init() error {
	g.Config = &oauth2.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		RedirectURL:  g.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
	g.Ctx = context.Background()
	return nil
}

func (g *OAuthGoogle) GetAuthorizeURLWithState(state string) string {
	return g.Config.AuthCodeURL(state)
}

func (g *OAuthGoogle) Exchange(code string) error {
	tok, err := g.Config.Exchange(g.Ctx, code)
	if err != nil {
		return err
	}
	g.Client = g.Config.Client(g.Ctx, tok)
	return nil
}

func (g *OAuthGoogle) FetchUserProfile() (*core.GoogleUserInfo, error) {
	resp, err := g.Client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result core.GoogleUserInfo
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
