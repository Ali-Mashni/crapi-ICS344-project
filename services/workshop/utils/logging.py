#
# Licensed under the Apache License, Version 2.0 (the “License”);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an “AS IS” BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import json
import logging
import os
from datetime import datetime


def log_security_event(event_name, user_id, action_details, severity="INFO"):
    log_dir = '/var/log/crapi'
    log_file = os.path.join(log_dir, 'workshop_security.jsonl')

    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
            os.chmod(log_dir, 0o777)
        except OSError:
            pass  # Fail silently if no directory permissions

    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "crapi-workshop",
        "severity": severity,
        "event_name": event_name,
        "user_id": str(user_id),
        "details": action_details
    }

    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logging.getLogger().error(f"Security Log Error: {e}")


def log_error(url, params, status_code, message):
    """
    :param url: The URL of the request API.
    :param params: Parameters of the request if any
    :param status_code: The return status code of the API
    :param message: The message of the error.
    :return:
    """
    logging.getLogger().error(f"{url} - {params} - {status_code} -{message}")
