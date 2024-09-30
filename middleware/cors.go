package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func CORSMiddleware(allowOrigin []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// add CORS allow origin for all clients
		reqOrigin := c.Request.Header.Get("Origin")

		// TODO: allow origin from whitelist only
		//helper.GetLogger().Debug("req origin %s", reqOrigin)
		//for _, o := range allowOrigin {
		//if o == reqOrigin {
		//}
		//}

		c.Writer.Header().Set("Access-Control-Allow-Origin", reqOrigin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, Content-Length, X-CSRF-Token, Token, session, Origin, Host, Connection, Accept-Encoding, Accept-Language, X-Requested-With")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Request.Header.Del("Origin")
		c.Next()
	}
}
