package module

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// XOR keys used for encryption
var sXors = []int{6, 7, 3, 5}

// Generate generates a unique identifier based on request details
func GenerateNewRlogId(poolName string, threadID int64) string {
	pageStartTime := time.Now().UnixNano() / int64(time.Millisecond)
	if threadID == 0 {
		threadID = 1
	}

	machineName := getMachineName(poolName, getHostName())
	ts := strconv.FormatInt(pageStartTime, 16)
	threadIDStr := fmt.Sprintf("0x%x", threadID)

	return fmt.Sprintf("%s-%s-%s", machineName, ts, threadIDStr)
}

func getMachineName(poolName string, hostname string) string {
	machineName := fmt.Sprintf("%s::%s", poolName, hostname)
	return url.QueryEscape(encrypt(machineName))
}

func encrypt(str string) string {
	encryptedStr := make([]byte, len(str))
	for i := range str {
		k := str[i]
		l := k ^ byte(sXors[i%4])
		encryptedStr[i] = l
	}
	return string(encryptedStr)
}

// func getPoolName() string {
// 	poolName := os.Getenv("PAAS_REALM")
// 	odbName := os.Getenv("ODBMO_NAME")

// 	if odbName != "" && poolName == "staging" {
// 		poolName = fmt.Sprintf("%s-%s", poolName, odbName)
// 	}

// 	calPoolName := os.Getenv("CONTAINER_PDLC")
// 	if calPoolName != "" {
// 		poolName = calPoolName
// 	}

// 	return poolName
// }

func getHostName() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return hostname
}
