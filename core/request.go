package core

type DareIdData struct {
	Id            int64 `json:"id"`
	Dareid        string
	WalletAddress *string
	Name          *string
	Email         *string
	Phone         *string
	Username      *string
	Description   *string
	AvatarUrl     *string
	EmailVerified *int32
	CreatedAt     string
	UpdatedAt     string
}

type RespGetDareIDByWallet struct {
	Code    int64 `json:"code"`
	Data    DareIdData
	Message string         `json:"message"`
	Google  GoogleUserInfo `json:"google"`
	Oauth   OauthToken     `json:"oauth"`
}

type RespGetProfile struct {
	Code     int64 `json:"code"`
	Data     DareIdData
	Message  string           `json:"message"`
	Oauth    OauthToken       `json:"oauth"`
	Google   GoogleUserInfo   `json:"google"`
	Twitter  TwitterUserInfo  `json:"twitter"`
	Telegram TelegramUserInfo `json:"telegram"`
}

type RespRefreshToken struct {
	Code    int64      `json:"code"`
	Message string     `json:"message"`
	Oauth   OauthToken `json:"oauth"`
}

type RespExchangeToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type RespGenerateChallenge struct {
	Code      int64  `json:"code"`
	Message   string `json:"message"`
	Challenge string `json:"challenge"`
	Hash      string `json:"hash"`
}

type DareAccount struct {
	ID            int64  `json:"id"`
	DareID        int64  `json:"Dareid"`
	WalletAddress string `json:"WalletAddress"`
}

type RespVerifyChallenge struct {
	Code    int64       `json:"code"`
	Message string      `json:"message"`
	Account AccountDare `json:"account"`
	Oauth   OauthToken  `json:"oauth"`
}

type RespValidateToken struct {
	Code    int64      `json:"code"`
	Message string     `json:"message"`
	Oauth   OauthToken `json:"oauth"`
	Dareid  string     `json:"dareid"`
}

type APIKey struct {
	APIKey string `json:"APIKey"`
}

type RespCreateAPIKey struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Secret  APIKey `json:"secret"`
}

type RespGetAPIKey struct {
	Code    int64    `json:"code"`
	Message string   `json:"message"`
	Secrets []APIKey `json:"secrets"`
}
