package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type CommonController struct {
}

func (ctrl *CommonController) Init() error {
	return nil
}

// @Summary Health check
// @ID HealthCheck
// @Produce application/json
// @Success 200 {object} SuccessResp
// @Failure 400 {object} BadRequestResp
// @Failure 500 {object} ServerErrorResp
// @Router /health [get]
func (ctrl *CommonController) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "service is healthy"})
}
