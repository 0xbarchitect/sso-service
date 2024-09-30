package helper

import (
	"fmt"
	"net/url"

	"github.com/dghubble/go-twitter/twitter"
)

func DecodeValueFromSession(values map[string]interface{}, key string) (string, error) {
	if val, ok := values[key]; ok {
		v := val.([]interface{})
		return v[0].(string), nil
	}
	return "", fmt.Errorf("key %s not found", key)
}

func EncodeUrlValues(values map[string]interface{}) (url.Values, error) {
	urlVal := make(map[string][]string)
	for key, val1 := range values {
		urlVal[key] = make([]string, 0)
		val2 := val1.([]interface{})
		for _, val := range val2 {
			urlVal[key] = append(urlVal[key], val.(string))
		}
	}
	return urlVal, nil
}

func DecodeTwitterUserFromSession(data interface{}) (*twitter.User, error) {
	dataMap := data.(map[string]interface{})

	dataStr := fmt.Sprintf("%s", data)
	GetLogger().Debug("data str %s", dataStr)

	tUser := twitter.User{}
	for k, v := range dataMap {
		GetLogger().Debug("key %s value %s", k, v)
	}
	return &tUser, nil
}
