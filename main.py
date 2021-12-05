#!/usr/bin/env python
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
import os
import sys

import time

from prometheus_client import start_http_server, Metric, REGISTRY
from prometheus_client.metrics_core import InfoMetricFamily

import wazuh

host = ""  # nosec
port = ""  # nosec
user = ""  # nosec
password = ""  # nosec
protocol = os.getenv("WAZUH_PROTOCOL", "https")
try:
    host = os.getenv("WAZUH_API_HOST")
    port = int(os.getenv("WAZUH_API_PORT"))
    user = os.getenv("WAZUH_API_USERNAME")
    password = os.getenv("WAZUH_API_PASSWORD")
    if not host or not port or not user or not password:
        raise KeyError
except KeyError as error:
    print("Please check system variables")
    sys.exit(2)

login_endpoint = "security/user/authenticate"


class WazuhCollector(object):
    def __init__(self):
        pass

    def collect(self):
        wazuh_connection = wazuh.Wazuh(
            protocol=protocol,
            host=host,
            port=port,
            login_endpoint=login_endpoint,
            user=user,
            password=password,
        )
        auth = wazuh_connection.login()
        agents = wazuh_connection.wazuh_get_agents_overview(auth)
        metric = Metric("wazuh_total_agent", "Total Wazuh agents count", "summary")
        for agent in agents["nodes"]:
            metric.add_sample("wazuh_agents_count", value=agent["count"], labels={})
        yield metric
        metric = Metric("wazuh_total_group", "Total Wazuh groups count", "summary")
        for group in agents["groups"]:
            metric.add_sample("wazuh_agents_group", value=group["count"], labels={})
        yield metric
        metric = Metric("wazuh_agent_status", "Total Wazuh agents by status", "summary")

        metric.add_sample(
            "wazuh_active_agents", value=agents["agent_status"]["active"], labels={}
        )
        metric.add_sample(
            "wazuh_disconnected_agents",
            value=agents["agent_status"]["disconnected"],
            labels={},
        )
        metric.add_sample(
            "wazuh_never_connected_agents",
            value=agents["agent_status"]["never_connected"],
            labels={},
        )
        metric.add_sample(
            "wazuh_pending_agents", value=agents["agent_status"]["pending"], labels={}
        )
        metric.add_sample(
            "wazuh_total_agents", value=agents["agent_status"]["total"], labels={}
        )
        yield metric
        metric = InfoMetricFamily("wazuh_agent_version", "Wazuh agent versions")
        for version in agents["agent_version"]:
            metric.add_metric(
                labels="version",
                value={"version": version["version"], "count": str(version["count"])},
            )

        yield metric
        metric = InfoMetricFamily(
            "last_registered_agent", "Wazuh last registered agent"
        )
        for version in agents["last_registered_agent"]:
            for key, value in version["os"].items():
                node_name = version["node_name"]
                node_value = f'{version["node_name"]}-{key}'
                prom_node_name_format = node_name.replace("-", "_")
                prom_node_value_format = node_value.replace("-", "_")

                metric.add_metric(
                    labels=prom_node_name_format,
                    value={prom_node_value_format: f"{value}"},
                )
        yield metric
        metric = InfoMetricFamily("nodes_healthcheck", "Wazuh nodes healthcheck")
        nodes = wazuh_connection.wazuh_get_nodes_healtchecks(auth)
        for node in nodes:
            for key, value in node["info"].items():
                metric.add_metric(
                    labels=node["info"]["name"], value={f"{key}": f"{value}"}
                )
        yield metric
        metric = InfoMetricFamily("wazuh_api", "Wazuh API information")
        info = wazuh_connection.wazuh_api_info(auth)
        for key, value in info.items():
            metric.add_metric(labels="wazuh_api_version", value={str(key): str(value)})
        yield metric


if __name__ == "__main__":
    print("Starting Wazuh prometheus exporter")
    start_http_server(5000)
    REGISTRY.register(WazuhCollector())

    while True:
        time.sleep(1)
