package middleware

import (
	"net/http"

	"sso/helper"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
)

func OauthMiddleware(oauthSrv *server.Server) gin.HandlerFunc {
	return func(c *gin.Context) {
		ti, err := oauthSrv.ValidationBearerToken(c.Request)
		if err != nil {
			helper.GetLogger().Error("validate token failed with error %s", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if ti == nil {
			helper.GetLogger().Error("token is nil")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("dareid", ti.GetUserID())
		c.Set("client_id", ti.GetClientID())

		c.Next()
	}
}
