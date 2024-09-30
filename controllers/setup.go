package controllers

const (
	LOGGED_UID_KEY = "LoggedInUserID"
	RETURN_URI_KEY = "ReturnUri"
)

type BadRequestResp struct {
	Error string `json:"error" example:"invalid request"`
}

type ServerErrorResp struct {
	Error string `json:"error" example:"db error"`
}

type SuccessResp struct {
	Code    int    `json:"code" example:"200"`
	Message string `json:"message" example:"Success"`
}
