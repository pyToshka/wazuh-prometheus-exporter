#  Copyright (c) 2021.  Yuriy Medvedev
#  All rights reserved.
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
#  following conditions are met: 1. Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer. 2. Redistributions in binary form must reproduce the above
#  copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
#  provided with the distribution. 3. All advertising materials mentioning features or use of this software must
#  display the following acknowledgement: This product includes software developed by the Yuriy Medvedev. 4.Neither
#  the name of the Yuriy Medvedev nor the names of its contributors may be used to endorse or promote products derived
#  from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY Yuriy Medvedev ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
#  BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL Yuriy Medvedev BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
#  OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import json
import requests
import urllib3
from base64 import b64encode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Wazuh:
    def __init__(self, protocol, host, port, login_endpoint, user, password):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.login_endpoint = login_endpoint
        self.user = user
        self.password = password
        self.url = f"{self.protocol}://{self.host}:{self.port}"

    def login(self):
        login_url = f"{self.url}/{self.login_endpoint}"
        basic_auth = f"{self.user}:{self.password}".encode()
        login_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {b64encode(basic_auth).decode()}",
        }
        response = requests.get(login_url, headers=login_headers, verify=False)  # nosec
        token = json.loads(response.content.decode())["data"]["token"]
        requests_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return requests_headers

    def wazuh_api_info(self, requests_headers):
        response = requests.get(
            f"{self.url}/", headers=requests_headers, verify=False  # nosec
        )
        return response.json()["data"]

    def wazuh_get_daemons_stat(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/status",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_base_info(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/info", headers=requests_headers, verify=False  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_configuration(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/configuration",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats", headers=requests_headers, verify=False  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_hourly_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/hourly",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_weekly_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/weekly",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_analysisd_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/analysisd",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_remote_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/remoted",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_logs(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/logs", headers=requests_headers, verify=False  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_logs_summary(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/logs/summary",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_agent_connection(self, requests_headers):
        response = requests.get(
            f"{self.url}/agents?pretty&offset=0&sort=status",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]

    def wazuh_get_agents_overview(self, requests_headers):
        response = requests.get(
            f"{self.url}/overview/agents",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]

    def wazuh_get_nodes_healtchecks(self, requests_headers):
        response = requests.get(
            f"{self.url}/cluster/healthcheck",
            headers=requests_headers,
            verify=False,  # nosec
        )
        return response.json()["data"]["affected_items"]
