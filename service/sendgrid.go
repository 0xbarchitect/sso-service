package service

import (
	"fmt"
	"os"
	"strings"

	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

const (
	SENDER_NAME = "SSO Service"
	SENDER_MAIL = "noreply@github.com"
)

var (
	_sendgridServiceIns SendgridServiceInf
)

func GetSendgridService() SendgridServiceInf {
	mu.Lock()
	defer mu.Unlock()
	return _sendgridServiceIns
}

func SetSendgridService(ins SendgridServiceInf) {
	mu.Lock()
	defer mu.Unlock()
	_sendgridServiceIns = ins
}

func NewSendgridService() (*SendgridService, error) {
	svc := &SendgridService{}
	err := svc.Init()
	return svc, err
}

type SendgridServiceInf interface {
	Init() error
	SendTemplatedEmail(recipient string, templateId string, redirectUrl string) (*rest.Response, error)
	SendEmailVerification(recipient string, ssoURL string, token string) (*rest.Response, error)
	SendRecoverPasswordEmail(recipient string, ssoURL string, token string) (*rest.Response, error)
}

type SendgridService struct {
	//Config *ini.File
	client *sendgrid.Client
}

func (s *SendgridService) Init() error {
	s.client = sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
	return nil
}

func (s *SendgridService) SendTemplatedEmail(recipient string, templateId string, redirectUrl string) (*rest.Response, error) {
	from := mail.NewEmail(SENDER_NAME, SENDER_MAIL)
	to := mail.NewEmail(strings.Split(recipient, "@")[0], recipient)

	// Create a new mail object
	message := mail.NewV3Mail()

	// Set the from and to email addresses
	message.SetFrom(from)
	personalization := mail.NewPersonalization()
	personalization.AddTos(to)

	// Set dynamic template data
	personalization.SetDynamicTemplateData("name", recipient)
	personalization.SetDynamicTemplateData("redirect_url", redirectUrl)

	// Add personalization to the message
	message.AddPersonalizations(personalization)

	// Set the template ID
	message.SetTemplateID(templateId)

	return s.client.Send(message)
}

func (s *SendgridService) SendEmailVerification(recipient string, ssoURL string, token string) (*rest.Response, error) {
	url := fmt.Sprintf("%s&access_token=%s", ssoURL, token)
	templateId := os.Getenv("SENDGRID_VERIFY_MAIL_TEMPLATE")
	return s.SendTemplatedEmail(recipient, templateId, url)
}

func (s *SendgridService) SendRecoverPasswordEmail(recipient string, ssoURL string, token string) (*rest.Response, error) {
	url := fmt.Sprintf("%s/change_password?access_token=%s", ssoURL, token)
	templateId := os.Getenv("SENDGRID_RECOVER_PASSWORD_TEMPLATE")
	return s.SendTemplatedEmail(recipient, templateId, url)
}
