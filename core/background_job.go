package core

const (
	MAIL_VERIFICATION_JOB = 1
)

type BackgroundJob struct {
	Type int
	Data map[string]string
}
