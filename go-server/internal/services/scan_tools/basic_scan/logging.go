package basicscan

import (
	"log"
)

func logValidationFailure(scope string, err error) {
	if err == nil {
		return
	}
	log.Printf("[basic_scan] validation failed (%s): %v", scope, err)
}
