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
import logging

import time

from prometheus_client import start_http_server, Metric, REGISTRY
from prometheus_client.metrics_core import InfoMetricFamily

import wazuh

logger = wazuh.get_logger()

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
    listen_port = os.getenv("EXPORTER_PORT", default="5000")
    if not host or not port or not user or not password:
        logger.critical(
            f"System variables are not set, please check."
            f" Wazuh host {host}, Wazuh port {port}, Wazuh api user {user}, Wazuh api password {password}"
        )
        raise KeyError
except KeyError as error:
    logger.critical(
        "Please check system variables. "
        "Wazuh host {host}, Wazuh port {port}, Wazuh api user {user}, Wazuh api password {password}"
    )
    sys.exit(2)

login_endpoint = "security/user/authenticate"


class WazuhCollector:
    def __init__(self):
        logger.info("Start collector")

    @staticmethod
    def collect():
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
        manager_stats_hourly = wazuh_connection.wazuh_get_hourly_stats(auth)
        manager_stats = wazuh_connection.wazuh_get_stats(auth)
        remote_stats = wazuh_connection.wazuh_get_remote_stats(auth)
        get_logs = wazuh_connection.wazuh_get_logs(auth)
        analysisd_stats = wazuh_connection.wazuh_get_analysisd_stats(auth)
        validate_configuration = wazuh_connection.wazuh_validate_configuration(auth)
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
            "wazuh_active_agents", value=agents["agent_status"]["connection"]["active"], labels={}
        )
        metric.add_sample(
            "wazuh_disconnected_agents",
            value=agents["agent_status"]["connection"]["disconnected"],
            labels={},
        )
        metric.add_sample(
            "wazuh_never_connected_agents",
            value=agents["agent_status"]["connection"]["never_connected"],
            labels={},
        )
        metric.add_sample(
            "wazuh_pending_agents", value=agents["agent_status"]["connection"]["pending"], labels={}
        )
        metric.add_sample(
            "wazuh_total_agents", value=agents["agent_status"]["connection"]["total"], labels={}
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
            if version["status"] == "never_connected":
                logging.warning(
                    f'Last Wazuh agent with name {version["name"]} has status {version["status"]},'
                    f"last_registered_agent metric has been skipped please check agent."
                    f"Full agent trace {version}"
                )
                pass
            else:
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
        metric = InfoMetricFamily(
            "manager_stats_hourly",
            "Wazuh statistical information per hour. "
            "Each number in the averages field represents the average of alerts per hour",
        )
        metric.add_sample(
            "total_affected_items",
            value=manager_stats_hourly["total_affected_items"],
            labels={},
        )
        metric.add_sample(
            "total_failed_items",
            value=manager_stats_hourly["total_failed_items"],
            labels={},
        )
        yield metric
        metric = InfoMetricFamily("nodes_healthcheck", "Wazuh nodes healthcheck")
        nodes = wazuh_connection.wazuh_get_nodes_healtchecks(auth)
        if nodes is None:
            pass
        else:
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
        metric = Metric(
            "manager_stats_total",
            "Wazuh statistical information for the current date",
            "summary",
        )
        for stats in manager_stats:
            metric.add_sample(
                f'total_alerts_hour_{stats["hour"]}',
                value=stats["totalAlerts"],
                labels={},
            )
            metric.add_sample(
                f'total_syscheck_hour_{stats["hour"]}',
                value=stats["syscheck"],
                labels={},
            )
            metric.add_sample(
                f'total_firewall_hour_{stats["hour"]}',
                value=stats["firewall"],
                labels={},
            )
            metric.add_sample(
                f'total_events_hour_{stats["hour"]}',
                value=stats["events"],
                labels={},
            )
        yield metric
        metric = Metric(
            "manager_stats_remote", "Wazuh remoted statistical information", "summary"
        )
        for remote_state in remote_stats:
            metric.add_sample(
                "queue_size",
                value=remote_state["queue_size"],
                labels={"manager_stats_remote": "queue_size"},
            )
            metric.add_sample(
                "total_queue_size",
                value=remote_state["total_queue_size"],
                labels={"manager_stats_remote": "total_queue_size"},
            )
            metric.add_sample(
                "tcp_sessions",
                value=remote_state["tcp_sessions"],
                labels={"manager_stats_remote": "tcp_sessions"},
            )
            metric.add_sample(
                "evt_count",
                value=remote_state["evt_count"],
                labels={"manager_stats_remote": "evt_count"},
            )
            metric.add_sample(
                "ctrl_msg_count",
                value=remote_state["ctrl_msg_count"],
                labels={"manager_stats_remote": "ctrl_msg_count"},
            )
            metric.add_sample(
                "discarded_count",
                value=remote_state["discarded_count"],
                labels={"manager_stats_remote": "discarded_count"},
            )
            metric.add_sample(
                "queued_msgs",
                value=remote_state["queued_msgs"],
                labels={"manager_stats_remote": "queued_msgs"},
            )
            metric.add_sample(
                "recv_bytes",
                value=remote_state["recv_bytes"],
                labels={"manager_stats_remote": "recv_bytes"},
            )
            metric.add_sample(
                "dequeued_after_close",
                value=remote_state["dequeued_after_close"],
                labels={"manager_stats_remote": "dequeued_after_close"},
            )
        yield metric
        metric = InfoMetricFamily("last_logs", "The last 2000 wazuh log entries")
        for log in get_logs:
            metric.add_metric(
                labels=f'wazuh_last_logs_{log["tag"]}',
                value={
                    f'{log["tag"].replace("-", "_").replace(":", "_")}_{log["level"]}': f'{log["description"].strip()}'
                },
            )
        yield metric
        metric = Metric(
            "analysisd_stats", "Wazuh analysisd statistical information", "summary"
        )
        for analysisd_stat in analysisd_stats:
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["total_events_decoded"],
                labels={"analysisd_stats": "total_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscheck_events_decoded"],
                labels={"analysisd_stats": "syscheck_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscheck_edps"],
                labels={"analysisd_stats": "syscheck_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscollector_events_decoded"],
                labels={"analysisd_stats": "syscollector_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscollector_edps"],
                labels={"analysisd_stats": "syscollector_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["rootcheck_events_decoded"],
                labels={"analysisd_stats": "rootcheck_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["rootcheck_edps"],
                labels={"analysisd_stats": "rootcheck_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["sca_events_decoded"],
                labels={"analysisd_stats": "sca_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["sca_edps"],
                labels={"analysisd_stats": "sca_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["hostinfo_events_decoded"],
                labels={"analysisd_stats": "hostinfo_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["hostinfo_edps"],
                labels={"analysisd_stats": "hostinfo_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["winevt_events_decoded"],
                labels={"analysisd_stats": "winevt_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["winevt_edps"],
                labels={"analysisd_stats": "winevt_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["dbsync_messages_dispatched"],
                labels={"analysisd_stats": "dbsync_messages_dispatched"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["dbsync_mdps"],
                labels={"analysisd_stats": "dbsync_mdps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["other_events_decoded"],
                labels={"analysisd_stats": "other_events_decoded"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["other_events_edps"],
                labels={"analysisd_stats": "other_events_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["events_processed"],
                labels={"analysisd_stats": "events_processed"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["events_edps"],
                labels={"analysisd_stats": "events_edps"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["events_received"],
                labels={"analysisd_stats": "events_received"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["events_dropped"],
                labels={"analysisd_stats": "events_dropped"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["alerts_written"],
                labels={"analysisd_stats": "alerts_written"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["firewall_written"],
                labels={"analysisd_stats": "firewall_written"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["fts_written"],
                labels={"analysisd_stats": "fts_written"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscheck_queue_usage"],
                labels={"analysisd_stats": "syscheck_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscheck_queue_size"],
                labels={"analysisd_stats": "syscheck_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscollector_queue_usage"],
                labels={"analysisd_stats": "syscollector_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["syscollector_queue_size"],
                labels={"analysisd_stats": "syscollector_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["rootcheck_queue_usage"],
                labels={"analysisd_stats": "rootcheck_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["rootcheck_queue_size"],
                labels={"analysisd_stats": "rootcheck_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["sca_queue_usage"],
                labels={"analysisd_stats": "sca_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["sca_queue_size"],
                labels={"analysisd_stats": "sca_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["sca_queue_size"],
                labels={"analysisd_stats": "sca_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["hostinfo_queue_usage"],
                labels={"analysisd_stats": "hostinfo_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["hostinfo_queue_size"],
                labels={"analysisd_stats": "hostinfo_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["winevt_queue_usage"],
                labels={"analysisd_stats": "winevt_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["dbsync_queue_usage"],
                labels={"analysisd_stats": "dbsync_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["dbsync_queue_size"],
                labels={"analysisd_stats": "dbsync_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["upgrade_queue_usage"],
                labels={"analysisd_stats": "upgrade_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["upgrade_queue_size"],
                labels={"analysisd_stats": "upgrade_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["event_queue_usage"],
                labels={"analysisd_stats": "event_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["event_queue_size"],
                labels={"analysisd_stats": "event_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["rule_matching_queue_usage"],
                labels={"analysisd_stats": "rule_matching_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["rule_matching_queue_size"],
                labels={"analysisd_stats": "rule_matching_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["alerts_queue_usage"],
                labels={"analysisd_stats": "alerts_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["alerts_queue_size"],
                labels={"analysisd_stats": "alerts_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["firewall_queue_usage"],
                labels={"analysisd_stats": "firewall_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["statistical_queue_usage"],
                labels={"analysisd_stats": "statistical_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["statistical_queue_size"],
                labels={"analysisd_stats": "statistical_queue_size"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["archives_queue_usage"],
                labels={"analysisd_stats": "archives_queue_usage"},
            )
            metric.add_sample(
                "analysisd_stats",
                value=analysisd_stat["archives_queue_size"],
                labels={"analysisd_stats": "archives_queue_size"},
            )

        yield metric
        metric = InfoMetricFamily(
            "wazuh_validate_configuration",
            "Return whether the Wazuh configuration is correct",
        )
        for validate in validate_configuration:
            metric.add_metric(
                labels=f'wazuh_{validate["name"]}',
                value={
                    "status": f'{validate["status"].strip()}',
                    "node_name": f'{validate["name"]}',
                },
            )
        yield metric


if __name__ == "__main__":
    logger.info("Starting Wazuh prometheus exporter")
    start_http_server(int(listen_port))
    REGISTRY.register(WazuhCollector())

    while True:
        time.sleep(1)
