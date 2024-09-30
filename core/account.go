package core

type AccountCore struct {
	Email      string
	Password   string
	WalletAddr string
}

type OauthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expires      int32  `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

type TwitterUserInfo struct {
	Uid           string
	Username      string
	ProfileImage  string
	Name          string
	Email         string
	FriendCount   int
	FollowerCount int
}

type TelegramUserInfo struct {
	Uid       string
	Username  string
	FirstName string
	LastName  string
}

type AccountSSO struct {
	Uid           string
	WalletAddress string
	Email         string
}

type AccountAPI struct {
	Email     string
	Password  string
	Username  string
	AvatarUrl string
}
