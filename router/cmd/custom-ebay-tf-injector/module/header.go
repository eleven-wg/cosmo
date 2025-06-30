package module

import (
	"log"
	"net/http"
	"strings"
)

const X_EBAY_C_REQUEST_ID = "X-EBAY-C-REQUEST-ID"

func GetRci(r *http.Request) string {
	requestIdHeader := r.Header.Get(X_EBAY_C_REQUEST_ID)
	if requestIdHeader == "" {
		log.Println("X-EBAY-C-REQUEST-ID header not found")
		return ""
	}
	parts := strings.Split(requestIdHeader, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "rci=") {
			return strings.TrimPrefix(part, "rci=")
		}
	}
	return ""
}

func GetRi(r *http.Request) string {
	requestIdHeader := r.Header.Get(X_EBAY_C_REQUEST_ID)
	if requestIdHeader == "" {
		log.Println("X-EBAY-C-REQUEST-ID header not found")
		return ""
	}
	parts := strings.Split(requestIdHeader, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "ri=") {
			return strings.TrimPrefix(part, "ri=")
		}
	}
	return ""
}
