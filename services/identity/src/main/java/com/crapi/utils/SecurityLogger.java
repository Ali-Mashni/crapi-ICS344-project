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

package com.crapi.utils;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SecurityLogger {
  private static final String LOG_PATH = "/var/log/crapi/identity_security.jsonl";
  private static final Gson gson = new Gson();

  /**
   * Returns the value of the {@code X-Request-ID} request header, or a freshly generated UUID if
   * the header is absent or blank.
   */
  public static String getOrGenerateRequestId(HttpServletRequest request) {
    String requestId = request.getHeader("X-Request-ID");
    if (requestId == null || requestId.isEmpty()) {
      requestId = UUID.randomUUID().toString();
    }
    return requestId;
  }

  public static void logEvent(
      String eventName, String userEmail, Map<String, Object> details, String severity) {
    try {
      File dir = new File("/var/log/crapi");
      if (!dir.exists()) dir.mkdirs();

      Map<String, Object> logEntry = new HashMap<>();
      logEntry.put("timestamp", Instant.now().toString());
      logEntry.put("service", "crapi-identity");
      logEntry.put("severity", severity);
      logEntry.put("event_name", eventName);
      logEntry.put("user_email", userEmail);
      logEntry.put("details", details);

      try (FileWriter fw = new FileWriter(LOG_PATH, true)) {
        fw.write(gson.toJson(logEntry) + "\n");
      }
    } catch (IOException e) {
      System.err.println("Failed to write security log: " + e.getMessage());
    }
  }
}
