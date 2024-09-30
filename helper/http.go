package helper

import (
	"encoding/json"
)

var (
	_httpHelperIns *HttpHelper
)

func SetHttpHelper(ins *HttpHelper) {
	mu.Lock()
	defer mu.Unlock()
	_httpHelperIns = ins
}

func GetHttpHelper() *HttpHelper {
	mu.Lock()
	defer mu.Unlock()
	return _httpHelperIns
}

type HttpHelper struct{}

func (h *HttpHelper) EncodingRespData(input interface{}, output interface{}) error {
	// vI := reflect.ValueOf(input)
	// typeOfSI := vI.Type()
	// vO := reflect.ValueOf(input)
	// typeOfSO := vO.Type()

	// for i := 0; i < vI.NumField(); i++ {
	// 	fmt.Printf("Field: %s\tValue: %v\n", typeOfSI.Field(i).Name, vI.Field(i).Interface())

	// 	for j := 0; j < vO.NumField(); j++ {
	// 		if typeOfSI.Field(i).Name == typeOfSO.Field(j).Name {
	// 			vO.Field(j).Interface() = vI.Field(i).Interface()
	// 		}
	// 	}
	// }

	inputJson, err := json.Marshal(input)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(inputJson, output); err != nil {
		return err
	}

	return nil
}
