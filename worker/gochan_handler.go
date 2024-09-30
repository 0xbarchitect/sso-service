package worker

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sso/core"
	"sso/helper"
	"sso/models"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"

	oauthmodels "github.com/go-oauth2/oauth2/v4/models"
)

const (
	AUTORELOAD_INTERVAL = 15 * time.Second
)

var (
	clientHash string
)

func BackgroundJobHandler(jobChan chan core.BackgroundJob, oauthSrv *server.Server, demoClientId string, demoClientSecret string, ssoURL string) {
	helper.GetLogger().Info("start background job handler...")
	for {
		select {
		case job := <-jobChan:
			helper.GetLogger().Debug("receive background job type %d with data %s", job.Type, job.Data)
			switch job.Type {
			case core.MAIL_VERIFICATION_JOB:
				dareid, ok := job.Data["dareid"]
				if !ok {
					helper.GetLogger().Error("not found dareid in job")
					continue
				}
				if _, ok := job.Data["email"]; !ok {
					helper.GetLogger().Error("not found email in job")
					continue
				}

				// oauth2 token
				gt := oauth2.GrantType("password")
				tgr := &oauth2.TokenGenerateRequest{
					ClientID:     demoClientId,
					ClientSecret: demoClientSecret,
					Request:      &http.Request{},
					Scope:        "email_verification",
					UserID:       dareid,
				}
				if _, err := oauthSrv.GetAccessToken(context.Background(), gt, tgr); err != nil {
					helper.GetLogger().Error("get oauth token failed with error %s", err)
					continue
				}
			default:
				helper.GetLogger().Debug("invalid job")
			}
		}
	}
}

func encodeClientHash() (*[]models.Client, string, error) {
	oauthClients, err := models.GetClientRepository().GetOauthClients()
	if err != nil {
		return oauthClients, "", err
	}

	var ingest string
	for _, cli := range *oauthClients {
		ingest += fmt.Sprintf("%d_%s_%s_%s", cli.ID, cli.ClientId, cli.ClientSecret, cli.RedirectUrl)
	}

	digest := helper.NewSHA256([]byte(ingest))
	return oauthClients, digest, nil
}

func AutoreloadClient(manager *manage.Manager, clientStore *store.ClientStore, demoClientId string, demoClientSecret string, demoClientUrl string) {
	var err error
	_, clientHash, err = encodeClientHash()
	helper.GetLogger().Info("client hash initiated %s", clientHash)

	timer := time.NewTicker(AUTORELOAD_INTERVAL)
	for {
		select {
		case <-timer.C:
			var clients *[]models.Client
			var digest string
			clients, digest, err = encodeClientHash()
			if err != nil {
				helper.GetLogger().Error("encode error %s", err)
			} else {
				//helper.GetLogger().Debug("generate digest %s", digest)
				if clientHash != digest {
					helper.GetLogger().Info("hash mismatched, do clients update...")
					newStore := store.NewClientStore()
					// client demo
					newStore.Set(demoClientId, &oauthmodels.Client{
						ID:     demoClientId,
						Secret: demoClientSecret,
						Domain: demoClientUrl,
					})
					helper.GetLogger().Debug("set client demo %s to client-store", demoClientId)

					for _, cli := range *clients {
						helper.GetLogger().Info("set client %s to client-store", cli.ClientId)
						newStore.Set(cli.ClientId, &oauthmodels.Client{
							ID:     cli.ClientId,
							Secret: cli.ClientSecret,
							Domain: cli.RedirectUrl,
						})
					}
					clientHash = digest
					//clientStore = newStore
					manager.MapClientStorage(newStore)
				}
			}
		}
	}
}
