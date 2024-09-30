package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	ginSession "github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"

	redisSession "github.com/go-session/redis"
	"github.com/go-session/session"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	oauthmodels "github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"

	swaggerDocs "sso/docs" // docs is generated by Swag CLI

	"sso/controllers"
	"sso/core"
	"sso/helper"
	"sso/middleware"
	"sso/models"
	"sso/service"
	"sso/worker"

	"github.com/dgrijalva/jwt-go"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	oRedisTokenStorage "github.com/go-oauth2/redis/v4"
	oRedis "github.com/go-redis/redis/v8"

	"github.com/joho/godotenv"
)

var (
	logger      *helper.Logger
	sfGenerator *service.SFGenerator

	// jwt helper
	jwtSecretKey string
	jwtHelper    *helper.JWTHelper

	// repositories
	accountRepository *models.AccountRepository
	clientRepository  *models.ClientRepository

	// services
	sendgridService *service.SendgridService

	// oauth2 server
	clientStore *store.ClientStore
	oauthSrv    *server.Server

	// client demo
	demoClientId, demoClientSecret, demoClientUrl, demoCodeChallenge string
	ssoURL                                                           string
	telegramBotName                                                  string

	// oauth clients
	googleOAuth *service.OAuthGoogle

	// server settings
	sessionSecret string
	cookieDomain  string
	cookieTTL     int
	redisHost     string
	redisPort     string

	// go channels
	jobChan chan core.BackgroundJob

	// TODO: prometheus metrics
	monitorChan chan string
	rpcSuccess  prometheus.Counter
	rpcError    prometheus.Counter
	rpcReqTime  *prometheus.HistogramVec
)

func init() {
	var err error

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file")
	}

	// logger
	logger, err = helper.NewLogger(os.Getenv("APP_MODE"), true)
	if err != nil {
		fmt.Printf("init logs failed with error %s", err)
		panic(err)
	}
	helper.SetLogger(logger)

	// global settings
	sessionSecret = os.Getenv("SESSION_SECRET")
	cookieDomain = os.Getenv("COOKIE_DOMAIN")
	cookieTTL, err = strconv.Atoi(os.Getenv("COOKIE_TTL"))
	if err != nil {
		helper.GetLogger().Error("parsing cookie TTL failed with error %s", err)
		panic(err)
	}

	// jwt
	jwtSecretKey = os.Getenv("JWT_SECRET_KEY")
	jwtHelper = helper.NewJWTHelper(jwtSecretKey)
	helper.SetJwtHelper(jwtHelper)

	// snowflake id generator
	sfGenerator = &service.SFGenerator{}
	service.SetSFGenerator(sfGenerator)

	// connect db
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"), os.Getenv("POSTGRES_PORT"))
	if os.Getenv("POSTGRES_SSLMODE") == "false" {
		dsn += " sslmode=disable"
	}
	err = models.ConnectDB(dsn)
	if err != nil {
		helper.GetLogger().Error("connect DB failed with error %s", err)
		panic(err)
	}
	helper.GetLogger().Info("Connect DB with dsn:%s success...", dsn)

	// data repositories
	accountRepository = &models.AccountRepository{}
	models.SetAccountRepository(accountRepository)

	clientRepository = &models.ClientRepository{}
	models.SetClientRepository(clientRepository)

	// redis config
	redisHost = os.Getenv("REDIS_HOST")
	redisPort = os.Getenv("REDIS_PORT")

	//sendgrid service
	sendgridService, err = service.NewSendgridService()
	if err != nil {
		helper.GetLogger().Error("init Sendgrid failed with error %s", err)
		panic(err)
	}
	service.SetSendgridService(sendgridService)
	helper.GetLogger().Info("Sendgrid connect success...")

	// google oauth
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	googleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

	googleOAuth, err = service.NewOAuthGoogle(googleClientID, googleClientSecret, googleRedirectURL)
	if err != nil {
		helper.GetLogger().Error("init Google client failed with error %s", err)
		panic(err)
	}
	service.SetGoogleOauth(googleOAuth)
	helper.GetLogger().Info("init Google client success...")

	// go channels
	jobChan = make(chan core.BackgroundJob)

	// TODO: prometheus metrics
	monitorChan = make(chan string)

	rpcSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rpclb_rpc_success_total",
		Help: "RPC Load Balancer - The total number of RPC call success",
	})

	rpcError = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rpclb_rpc_error_total",
		Help: "RPC Load Balancer - The total number of RPC call error",
	})

	rpcReqTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "rpclb_rpc_req_time",
		Help:    "RPC Load Balancer - RPC request processing time",
		Buckets: prometheus.LinearBuckets(0, 500, 20), // 5 buckets, each 5 centigrade wide.
	}, []string{"endpoint"})

	// demo client
	demoClientUrl = fmt.Sprintf("%s/oauth2", os.Getenv("DEMO_CLIENT_URL"))
	demoClientId = os.Getenv("DEMO_CLIENT_ID")
	demoClientSecret = os.Getenv("DEMO_CLIENT_SECRET")
	demoCodeChallenge = os.Getenv("DEMO_CODE_CHALLENGE")
	ssoURL = os.Getenv("SSO_URL")
}

// @title SSO
// @version 1.0
// @description All-in-one SSO Service
// @contact.url https://github.com/0xbarchitect
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @BasePath /
// @securityDefinitions.apikey JwtHeader
// @in header
// @name Authorization
// @securityDefinitions.basic  ClientBasicAuth
func main() {
	// init http server
	http_address := fmt.Sprintf("%s:%s", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT"))
	oauthSrv = setupOAuth2()
	// background job handler
	go worker.BackgroundJobHandler(jobChan, oauthSrv, demoClientId, demoClientSecret, ssoURL)

	r := setupRouter()
	helper.GetLogger().Info("SSO server started at http://%s", http_address)
	log.Fatal(r.Run(http_address))
}

func setupRouter() *gin.Engine {
	// Creates a router without any middleware by default
	r := gin.New()
	r.Use(helper.HTTPRequestLogger())
	r.Use(gin.Recovery())

	r.GET("/swagger/*any", func(context *gin.Context) {
		swaggerDocs.SwaggerInfo.Host = context.Request.Host
		ginSwagger.WrapHandler(swaggerFiles.Handler)(context)
	})

	// CORS allow all
	r.Use(middleware.CORSMiddleware([]string{}))

	commonController := controllers.CommonController{}
	commonController.Init()

	// go-session using redis store
	session.InitManager(
		session.SetStore(redisSession.NewRedisStore(
			&redisSession.Options{
				Addr: fmt.Sprintf("%s:%s", redisHost, redisPort),
			},
		)),
	)

	// register interface for gin-session
	gob.Register(url.Values{})

	// session store
	//store, err := redis.NewStore(10, "tcp", redisHost+":"+redisPort, redisPass, []byte(sessionSecret))
	store, err := redis.NewStoreWithDB(10, "tcp", redisHost+":"+redisPort, "", strconv.Itoa(0), []byte(sessionSecret))
	if err != nil {
		helper.GetLogger().Error("init session redis store failed with error %s", err)
		panic(err)
	}

	r.Use(ginSession.Sessions("sso-session", store))
	helper.GetLogger().Info("init session store redis success...")

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "sso server is running..."})
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler())) // prometheus monitoring

	r.GET("/health", commonController.HealthCheck) // health-check endpoint

	// basic auth middleware
	ginAccounts, err := clientRepository.GetGinAccounts()
	if err != nil {
		helper.GetLogger().Error("not found authorized client")
	}

	// add demo-client to basic auth
	(*ginAccounts)[demoClientId] = demoClientSecret

	clientAuthorized := r.Group("/", gin.BasicAuth(*ginAccounts))
	helper.GetLogger().Info("setup client auth middleware success...")

	clientAuthorized.GET("/get_profile_by_dareid/:dareid", controllers.GetProfileByDareid) // only system services is authorized

	userAuthorized := r.Group("/", middleware.OauthMiddleware(oauthSrv))
	helper.GetLogger().Info("setup user oauth middleware success...")

	userAuthorized.GET("/get_profile", controllers.GetProfile)
	userAuthorized.POST("/update_profile", controllers.UpdateProfile)

	userAuthorized.POST("/create-api-key", controllers.CreateAPIKey)
	userAuthorized.GET("/get-api-key", controllers.GetAPIKey)
	userAuthorized.DELETE("/delete-api-key", controllers.DeleteAPIKey)

	// signup & login form
	r.GET("/login", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		c.Set("job_channel", jobChan)
		c.Set("ssoURL", ssoURL)
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		c.Set("clientRedirectURL", demoClientUrl)
		c.Set("codeChallenge", demoCodeChallenge)
		controllers.LoginHandler(c)
	})
	r.POST("/login", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		c.Set("job_channel", jobChan)
		c.Set("ssoURL", ssoURL)
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		c.Set("clientRedirectURL", demoClientUrl)
		c.Set("codeChallenge", demoCodeChallenge)
		controllers.LoginHandler(c)
	})

	r.GET("/signup", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		c.Set("job_channel", jobChan)
		c.Set("ssoURL", ssoURL)
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		c.Set("clientRedirectURL", demoClientUrl)
		c.Set("codeChallenge", demoCodeChallenge)
		controllers.SignupHandler(c)
	})
	r.POST("/signup", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		c.Set("job_channel", jobChan)
		c.Set("ssoURL", ssoURL)
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		c.Set("clientRedirectURL", demoClientUrl)
		c.Set("codeChallenge", demoCodeChallenge)
		controllers.SignupHandler(c)
	})

	r.GET("/auth", func(c *gin.Context) {
		// cookie settings
		c.Set("cookieDomain", cookieDomain)
		controllers.AuthHandler(c)
	})
	r.POST("/auth", func(c *gin.Context) {
		// cookie settings
		c.Set("cookieDomain", cookieDomain)
		controllers.AuthHandler(c)
	})

	// recover password
	r.POST("/recover_password", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv) // inject oauth server into ctx
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		c.Set("ssoURL", ssoURL)
		controllers.RecoverPassword(c)
	})

	r.GET("/change_password", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv) // inject oauth server into ctx
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		controllers.ChangePassword(c)
	})
	r.POST("/change_password", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv) // inject oauth server into ctx
		c.Set("clientId", demoClientId)
		c.Set("clientSecret", demoClientSecret)
		controllers.ChangePassword(c)
	})

	// oauth handler
	r.GET("/oauth/authorize", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		controllers.OauthAuthorizeHandler(c)
	})

	r.POST("/oauth/authorize", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		controllers.OauthAuthorizeHandler(c)
	})

	clientAuthorized.POST("/oauth/token", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		controllers.OauthTokenHandler(c)
	})

	r.GET("/oauth/validate-token", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		controllers.ValidateToken(c)
	})

	// connect social identity
	r.GET("/connect/:provider", func(c *gin.Context) {
		// cookie settings
		c.Set("cookieDomain", cookieDomain)
		c.Set("cookieTTL", cookieTTL)

		c.Set("oauthServer", oauthSrv)
		// client demo config
		c.Set("clientDemoId", demoClientId)
		c.Set("botName", telegramBotName)
		controllers.ConnectIdentityProvider(c)
	})

	r.GET("/authorized/google", func(c *gin.Context) {
		// set cookie to save redirect url
		c.Set("cookieDomain", cookieDomain)
		c.Set("cookieTTL", cookieTTL)

		controllers.GoogleAuthorizedReq(c)
	})
	r.GET("/authorized/google_handler", func(c *gin.Context) {
		c.Set("oauthServer", oauthSrv)
		controllers.GoogleOauthHandler(c)
	})

	r.GET("/connect/google_handler", func(c *gin.Context) {
		// client demo config
		c.Set("clientDemoId", demoClientId)
		controllers.GoogleConnectHandler(c)
	})

	// wallet challenge
	r.POST("/generate-challenge", controllers.GenerateChallenge)
	clientAuthorized.POST("/verify-challenge", func(c *gin.Context) {
		c.Set("demoClientId", demoClientId)
		c.Set("demoClientSecret", demoClientSecret)
		c.Set("oauthServer", oauthSrv)
		controllers.VerifyChallenge(c)
	})

	r.POST("/regist-account", controllers.RegistAccountHandler)

	return r
}

func setupOAuth2() *server.Server {
	// oauth2 server
	manager := manage.NewDefaultManager()
	//manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// config token TTL
	accessTokenTTL := os.Getenv("ACCESS_TOKEN_TTL")
	refreshTokenTTL := os.Getenv("REFRESH_TOKEN_TTL")
	at, err := strconv.Atoi(accessTokenTTL)
	if err != nil {
		helper.GetLogger().Error("access token ttl parsing error %s", err)
		panic(err)
	}
	rt, err := strconv.Atoi(refreshTokenTTL)
	if err != nil {
		helper.GetLogger().Error("refresh token ttl parsing error %s", err)
		panic(err)
	}

	// token config
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    time.Minute * time.Duration(at),
		RefreshTokenExp:   time.Minute * time.Duration(rt),
		IsGenerateRefresh: true,
	})

	manager.SetPasswordTokenCfg(&manage.Config{
		AccessTokenExp:    time.Minute * time.Duration(at),
		RefreshTokenExp:   time.Minute * time.Duration(rt),
		IsGenerateRefresh: true,
	})

	manager.SetClientTokenCfg(&manage.Config{
		AccessTokenExp: time.Minute * time.Duration(at),
	})

	// token store utilizes redis
	//manager.MustTokenStorage(store.NewMemoryTokenStore())

	manager.MapTokenStorage(oRedisTokenStorage.NewRedisStore(&oRedis.Options{
		Addr: fmt.Sprintf("%s:%s", redisHost, redisPort),
	}))
	helper.GetLogger().Info("oauth server setup redis token store success...")

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte(jwtSecretKey), jwt.SigningMethodHS512))

	clientStore = store.NewClientStore()
	// client demo
	clientStore.Set(demoClientId, &oauthmodels.Client{
		ID:     demoClientId,
		Secret: demoClientSecret,
		Domain: demoClientUrl,
	})
	helper.GetLogger().Debug("set client demo %s to client-store", demoClientId)
	// fetch client info from DB
	oauthClients, err := clientRepository.GetOauthClients()
	if err != nil {
		helper.GetLogger().Error("not found any oauth clients in DB!!!")
	} else {
		for _, cli := range *oauthClients {
			helper.GetLogger().Info("set client %s to client-store", cli.ClientId)
			clientStore.Set(cli.ClientId, &oauthmodels.Client{
				ID:     cli.ClientId,
				Secret: cli.ClientSecret,
				Domain: cli.RedirectUrl,
			})
		}
	}

	// auto reload clients info
	go worker.AutoreloadClient(manager, clientStore, demoClientId, demoClientSecret, demoClientUrl)

	manager.MapClientStorage(clientStore)
	manager.SetValidateURIHandler(controllers.ValidateClientRedirectURI)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(controllers.PasswordAuthorizationHandler)

	srv.SetUserAuthorizationHandler(controllers.UserAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		helper.GetLogger().Error("Internal Error: %s", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		helper.GetLogger().Error("Response Error: %s", re.Error.Error())
	})

	return srv
}
