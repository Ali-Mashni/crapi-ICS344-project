/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SecurityLog represents a structured security event log entry.
type SecurityLog struct {
	Timestamp string                 `json:"timestamp"`
	Service   string                 `json:"service"`
	Severity  string                 `json:"severity"`
	EventName string                 `json:"event_name"`
	UserEmail string                 `json:"user_email"`
	Details   map[string]interface{} `json:"details"`
}

// LogSecurityEvent writes a JSON-structured security event to the community log file.
func LogSecurityEvent(eventName, userEmail, severity string, details map[string]interface{}) {
	logDir := "/var/log/crapi"
	logFile := logDir + "/community_security.jsonl"

	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.MkdirAll(logDir, 0777)
	}

	event := SecurityLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Service:   "crapi-community",
		Severity:  severity,
		EventName: eventName,
		UserEmail: userEmail,
		Details:   details,
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		fmt.Println("Error marshalling security log:", err)
		return
	}

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Error opening security log file:", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(append(jsonData, '\n')); err != nil {
		fmt.Println("Error writing security log:", err)
	}
}
