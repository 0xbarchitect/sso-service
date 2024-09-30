package helper

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	loggerInstance *Logger
	mu             sync.Mutex
)

func SetLogger(ins *Logger) {
	mu.Lock()
	defer mu.Unlock()
	loggerInstance = ins
}

func GetLogger() *Logger {
	mu.Lock()
	defer mu.Unlock()
	return loggerInstance
}

func NewLogger(appMode string, stdout bool) (*Logger, error) {
	logger := &Logger{StdOutOnly: stdout}
	if appMode == "development" {
		logger._isDevelopment = true
	} else if appMode == "production" {
		logger._isProduction = true
	}

	err := logger.Init()
	return logger, err
}

type Logger struct {
	_isDevelopment bool
	_isProduction  bool
	StdOutOnly     bool
}

func (l *Logger) Init() error {
	return nil
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l._isDevelopment {
		log.Debug().Msgf(format, v...)
	}
}

func (l *Logger) Error(format string, v ...interface{}) {
	log.Error().Msgf(format, v...)
}

func (l *Logger) Warning(format string, v ...interface{}) {
	log.Warn().Msgf(format, v...)
}

func (l *Logger) Info(format string, v ...interface{}) {
	log.Info().Msgf(format, v...)
}

// HTTPRequestLogger logs a gin HTTP request in JSON format.
func HTTPRequestLogger() gin.HandlerFunc {
	return StructuredLogger(&log.Logger)
}

func StructuredLogger(logger *zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		start := time.Now() // Start timer
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Fill the params
		param := gin.LogFormatterParams{}

		param.TimeStamp = time.Now() // Stop timer

		param.Latency = param.TimeStamp.Sub(start)
		if param.Latency > time.Minute {
			param.Latency = param.Latency.Truncate(time.Second)
		}

		param.ClientIP = c.ClientIP()
		param.Method = c.Request.Method
		param.StatusCode = c.Writer.Status()
		param.ErrorMessage = c.Errors.ByType(gin.ErrorTypePrivate).String()
		param.BodySize = c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}
		param.Path = path

		// Log using the params
		var logEvent *zerolog.Event

		if c.Writer.Status() >= 400 {
			logEvent = logger.Error()
		}

		logEvent.Str("client_id", param.ClientIP).
			Str("method", param.Method).
			Int("status_code", param.StatusCode).
			Int("body_size", param.BodySize).
			Str("path", param.Path).
			Str("latency", param.Latency.String()).
			Msg(param.ErrorMessage)

	}
}
