#!/usr/bin/env python

import os
import sys

import time
from datetime import datetime, timezone

from prometheus_client import start_http_server, REGISTRY
from prometheus_client.metrics_core import InfoMetricFamily, GaugeMetricFamily, SummaryMetricFamily, HistogramMetricFamily

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
        manager_stats = wazuh_connection.wazuh_get_stats(auth)
        daemon_stats = wazuh_connection.wazuh_get_daemons_stats(auth)
        daemon_status = wazuh_connection.wazuh_get_daemons_status(auth)[0]  # this always returns a list with a single element, unwrap it here
        validate_configuration = wazuh_connection.wazuh_validate_configuration(auth)

        # Push metric for total agent count per node
        metric = GaugeMetricFamily(
            "wazuh_total_agent", 
            "Total Wazuh agents count", 
            labels=['node_name'])
        if len(agents['nodes']) == 0:
            metric.add_metric(value=0, labels={})
        else:
            agent_count_total = 0
            for agent in agents['nodes']:
                metric.add_metric(
                    labels=[agent['node_name']],
                    value=agent['count']
                )
                agent_count_total += agent["count"]
        yield metric

        # Push metrics for agent count per group
        metric = GaugeMetricFamily(
            "wazuh_total_group", 
            "Total Wazuh groups count", 
            labels=['group_name'])
        for group in agents['groups']:
            metric.add_metric(
                labels=[group['name']],
                value=group['count'])
        yield metric

        # Push metrics for agent status and counts per status
        metric = GaugeMetricFamily(
            "wazuh_agent_status", 
            "Total Wazuh agents by status", 
            labels=['status'])
        for conn_status, value in agents['agent_status']['connection'].items():
            metric.add_metric(
                labels=[conn_status],
                value=value
            )
        yield metric

        # Push metrics for agent versions and counts per version
        metric = GaugeMetricFamily(
            "wazuh_agent_version", 
            "Wazuh agent versions", 
            labels=['version'])
        for version in agents["agent_version"]:
            metric.add_metric(
                [version['version']],
                value=version['count'])
        yield metric

        # Push metrics for events and alerts stats
        for stats in manager_stats:
            event_metric = GaugeMetricFamily(
                "event_counts_last_hour", 
                "Count of last hour system events and alerts", 
                labels=["event_type"])
            alert_metric = GaugeMetricFamily(
                "alert_counts_by_level_last_hour", 
                "Count of last hour alerts by level and sigid", 
                labels=["sigid", "level"])
            if stats['hour'] == len(stats)-1:
                for item in stats:
                    if item == "alerts":
                        for sigid in stats[item]:
                            alert_metric.add_metric(
                                value=str(sigid['times']),
                                labels=[str(sigid['sigid']), str(sigid['level'])]
                            )
                        yield alert_metric
                    if item != "hour" and item != "alerts":
                        value=str(stats[item])
                        event_metric.add_metric(
                        value=value,
                        labels=[item]
                        )
                yield event_metric
            else:
                continue

        # Push metrics for Manager Daemon statuses (1.0 for up, 0.0 for down)
        metric = GaugeMetricFamily(
            "manager_daemons_status", 
            "status of daemons running on manager", 
            labels=["daemon", "state"])
        for daemon, status in daemon_status.items():
            if status == "running":
                value=1.0
            else:
                value=0.0
            metric.add_metric(
                value=str(value),
                labels=[daemon, status]
            )
        yield metric

        # Produce metrics for daemon status on manager
        metric = GaugeMetricFamily(
            "wazuh_manager_status",
            "Return whether the Wazuh manager is is healthy",
            labels=["status"])
        for validate in validate_configuration:
            if f'{validate["status"]}' == "OK":
                value = 1.0
            else:
                value = 0.0
            metric.add_metric(
                labels=[f'{validate["status"]}'],
                value=value)
        yield metric

        # Produce metrics for daemon stats
        unmonitored_daemons = 0  # in case future versions add new daemon stats that we aren't looking at
        for daemon in daemon_stats:
            daemon_metrics = daemon["metrics"]
            up_since = daemon["uptime"]
            uptime = (datetime.now(timezone.utc) - datetime.fromisoformat(up_since).replace(tzinfo=timezone.utc)).total_seconds()
            name = daemon["name"]

            # Remoted stat collection
            # Note, omitted queue size stats as they appear impertenint, should be added if releasing generally, or if neeeded later.  See output of /manager/daemons/stats API
            if name == "wazuh-remoted":
                metric = GaugeMetricFamily(
                    "manager_daemon_stats_remoted",
                    "Statistics for remoted daemon on manager",
                    labels=["remoted_metric"]
                )
                metric.add_metric(
                    labels=["uptime_seconds"],
                    value=str(uptime)
                )
                metric.add_metric(
                    labels=["bytes_received"],
                    value=f"{daemon_metrics['bytes']['received']}"
                )
                metric.add_metric(
                    labels=["bytes_sent"],
                    value=f"{daemon_metrics['bytes']['sent']}"
                )
                metric.add_metric(
                    labels=["key_reload_count"],
                    value=f"{daemon_metrics['keys_reload_count']}"
                )
                metric.add_metric(
                    labels=["queuesize"],
                    value=f"{daemon_metrics['queues']['received']['size']}"
                )

            # Analysisd stat collection
            elif name == "wazuh-analysisd":
                metric = GaugeMetricFamily(
                "manager_daemon_stats_analysisd",
                "Statistics for analysisd daemon on manager",
                labels=["analysisd_metric"]
                )
                metric.add_metric(
                    labels=["uptime_seconds"],
                    value=str(uptime)
                )
                metric.add_metric(
                    labels=["bytes_received"],
                    value=f"{daemon_metrics['bytes']['received']}"
                )
                metric.add_metric(
                    labels=["events_received"],
                    value=f"{daemon_metrics['events']['received']}"
                )
                metric.add_metric(
                    labels=["events_processed"],
                    value=f"{daemon_metrics['events']['processed']}"
                )
                metric.add_metric(
                    labels=["events_received_agent"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['agent']}"
                )
                metric.add_metric(
                    labels=["events_received_agentless"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['agentless']}"
                )
                metric.add_metric(
                    labels=["events_received_dbsync"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['dbsync']}"
                )
                metric.add_metric(
                    labels=["events_received_virustotal"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['integrations_breakdown']['virustotal']}"
                )
                metric.add_metric(
                    labels=["events_received_aws"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['aws']}"
                )
                metric.add_metric(
                    labels=["events_received_azure"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['azure']}"
                )
                metric.add_metric(
                    labels=["events_received_gcp"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['gcp']}"
                )
                metric.add_metric(
                    labels=["events_received_ciscat"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['ciscat']}"
                )
                metric.add_metric(
                    labels=["events_received_command"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['command']}"
                )
                metric.add_metric(
                    labels=["events_received_docker"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['docker']}"
                )
                metric.add_metric(
                    labels=["events_received_github"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['github']}"
                )
                metric.add_metric(
                    labels=["events_received_eventchannel"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['logcollector_breakdown']['eventchannel']}"
                )
                metric.add_metric(
                    labels=["events_received_eventlog"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['logcollector_breakdown']['eventlog']}"
                )
                metric.add_metric(
                    labels=["events_received_macos"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['logcollector_breakdown']['macos']}"
                )
                metric.add_metric(
                    labels=["events_received_other"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['logcollector_breakdown']['others']}"
                )
                metric.add_metric(
                    labels=["events_received_office365"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['office365']}"
                )
                metric.add_metric(
                    labels=["events_received_oscap"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['oscap']}"
                )
                metric.add_metric(
                    labels=["events_received_osquery"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['osquery']}"
                )
                metric.add_metric(
                    labels=["events_received_sca"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['sca']}"
                )
                metric.add_metric(
                    labels=["events_received_syscheck"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['syscheck']}"
                )
                metric.add_metric(
                    labels=["events_received_syscollector"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['syscollector']}"
                )
                metric.add_metric(
                    labels=["events_received_upgrade"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['upgrade']}"
                )
                metric.add_metric(
                    labels=["events_received_vulnerability"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['modules_breakdown']['vulnerability']}"
                )
                metric.add_metric(
                    labels=["events_received_monitor"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['monitor']}"
                )
                metric.add_metric(
                    labels=["events_received_remote"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['remote']}"
                )
                metric.add_metric(
                    labels=["events_received_syslog"],
                    value=f"{daemon_metrics['events']['received_breakdown']['decoded_breakdown']['syslog']}"
                )
                metric.add_metric(
                    labels=["events_dropped_agent"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['agent']}"
                )
                metric.add_metric(
                    labels=["events_dropped_agentless"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['agentless']}"
                )
                metric.add_metric(
                    labels=["events_dropped_dbsync"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['dbsync']}"
                )
                metric.add_metric(
                    labels=["events_dropped_virustotal"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['integrations_breakdown']['virustotal']}"
                )
                metric.add_metric(
                    labels=["events_dropped_aws"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['aws']}"
                )
                metric.add_metric(
                    labels=["events_dropped_azure"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['azure']}"
                )
                metric.add_metric(
                    labels=["events_dropped_gcp"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['gcp']}"
                )
                metric.add_metric(
                    labels=["events_dropped_ciscat"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['ciscat']}"
                )
                metric.add_metric(
                    labels=["events_dropped_command"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['command']}"
                )
                metric.add_metric(
                    labels=["events_dropped_docker"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['docker']}"
                )
                metric.add_metric(
                    labels=["events_dropped_github"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['github']}"
                )
                metric.add_metric(
                    labels=["events_dropped_eventchannel"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['logcollector_breakdown']['eventchannel']}"
                )
                metric.add_metric(
                    labels=["events_dropped_eventlog"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['logcollector_breakdown']['eventlog']}"
                )
                metric.add_metric(
                    labels=["events_dropped_macos"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['logcollector_breakdown']['macos']}"
                )
                metric.add_metric(
                    labels=["events_dropped_other"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['logcollector_breakdown']['others']}"
                )
                metric.add_metric(
                    labels=["events_dropped_office365"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['office365']}"
                )
                metric.add_metric(
                    labels=["events_dropped_oscap"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['oscap']}"
                )
                metric.add_metric(
                    labels=["events_dropped_osquery"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['osquery']}"
                )
                metric.add_metric(
                    labels=["events_dropped_sca"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['sca']}"
                )
                metric.add_metric(
                    labels=["events_dropped_syscheck"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['syscheck']}"
                )
                metric.add_metric(
                    labels=["events_dropped_syscollector"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['syscollector']}"
                )
                metric.add_metric(
                    labels=["events_dropped_upgrade"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['upgrade']}"
                )
                metric.add_metric(
                    labels=["events_dropped_vulnerability"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['modules_breakdown']['vulnerability']}"
                )
                metric.add_metric(
                    labels=["events_dropped_monitor"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['monitor']}"
                )
                metric.add_metric(
                    labels=["events_dropped_remote"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['remote']}"
                )
                metric.add_metric(
                    labels=["events_dropped_syslog"],
                    value=f"{daemon_metrics['events']['received_breakdown']['dropped_breakdown']['syslog']}"
                )
                metric.add_metric(
                    labels=["events_written_alerts"],
                    value=f"{daemon_metrics['events']['written_breakdown']['alerts']}"
                )
                metric.add_metric(
                    labels=["events_written_archives"],
                    value=f"{daemon_metrics['events']['written_breakdown']['archives']}"
                )
                metric.add_metric(
                    labels=["events_written_firewall"],
                    value=f"{daemon_metrics['events']['written_breakdown']['firewall']}"
                )
                metric.add_metric(
                    labels=["events_written_fts"],
                    value=f"{daemon_metrics['events']['written_breakdown']['fts']}"
                )
                metric.add_metric(
                    labels=["events_written_stats"],
                    value=f"{daemon_metrics['events']['written_breakdown']['stats']}"
                )
                for queue, data in daemon_metrics['queues'].items():
                    name = queue
                    size = data['size']
                    usage = data['usage']
                    metric.add_metric(
                        labels=[f"{name}_queue_size"],
                        value=str(size)
                    )
                    metric.add_metric(
                        labels=[f"{name}_queue_usage"],
                        value=usage
                    )
            elif name == "wazuh-db":
                metric = GaugeMetricFamily(
                "manager_daemon_stats_db",
                "Statistics for manager db",
                labels=["db_metric"]
                )
                metric.add_metric(
                    labels=["uptime_seconds"],
                    value=str(uptime)
                )
                metric.add_metric(
                    labels=["queries_received_total"],
                    value=f"{daemon_metrics['queries']['received']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_begin"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['begin']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_close"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['close']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_commit"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['commit']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_remove"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['remove']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_sql"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_vacuum"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['vacuum']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_get_fragmentation"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['db']['get_fragmentation']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_ciscat"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['ciscat']['ciscat']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_rootcheck"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['rootcheck']['rootcheck']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_sca"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['sca']['sca']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_dbsync"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['sync']['dbsync']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscheck_fim_file"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['fim_file']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscheck_fim_registry"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscheck"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscheck']['syscheck']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_hotfixes"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_hotfixes']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_hwinfo"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_hwinfo']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_network_address"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_network_address']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_network_iface"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_network_iface']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_network_protocol"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_network_protocol']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_osinfo"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_osinfo']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_packages"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_packages']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_ports"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_ports']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_syscollector_processes"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_processes']}"
                )
                metric.add_metric(
                    labels=["queries_received_agent_db_table_vulnerability"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['agent_breakdown']['tables']['vulnerability']['vuln_cves']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_total"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_backup"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['db']['backup']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_sql"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_vacuum"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['db']['vacuum']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_get_fragmentation"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['db']['get_fragmentation']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_delete_agent"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['delete-agent']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_disconnect_agent"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['disconnect-agents']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_find_agent"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['find-agent']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_get_agent_info"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['get-agent-info']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_get_agents_by_conn_status"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['get-agents-by-connection-status']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_get_all_agents"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['get-all-agents']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_get_distinct_groups"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['get-distinct-groups']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_get_groups_integrity"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['get-groups-integrity']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_insert_agent"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['insert-agent']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_reset_agent_conn"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['reset-agents-connection']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_select_agent_group"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['select-agent-group']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_select_agent_name"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['select-agent-name']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_set_agent_groups"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['set-agent-groups']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_sync_agent_groups_get"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['sync-agent-groups-get']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_sync_agent_info_get"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['sync-agent-info-get']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_sync_agent_info_set"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['sync-agent-info-set']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_update_agent_data"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['update-agent-data']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_update_agent_name"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['update-agent-name']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_update_connection_status"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['update-connection-status']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_agent_update_keepalive"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['agent']['update-keepalive']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_belongs_get_group_agents"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['belongs']['get-group-agents']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_belongs_select_group_belong"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['belongs']['select-group-belong']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_group_delete_group"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['group']['delete-group']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_group_find_group"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['group']['find-group']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_group_insert_agent_group"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['group']['insert-agent-group']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_group_select_groups"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['group']['select-groups']}"
                )
                metric.add_metric(
                    labels=["queries_received_global_db_tables_labels_get_labels"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['global_breakdown']['tables']['labels']['get-labels']}"
                )
                metric.add_metric(
                    labels=["queries_received_mitre"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['mitre']}"
                )
                metric.add_metric(
                    labels=["queries_received_mitre_db_sql"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['mitre_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["queries_received_task"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_sql"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_delete_old"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['delete_old']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_set_timeout"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['set_timeout']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_upgrade"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['upgrade']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_upgrade_cancel_tasks"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['upgrade_cancel_tasks']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_upgrade_custom"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['upgrade_custom']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_upgrade_get_status"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['upgrade_get_status']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_upgrade_result"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['upgrade_result']}"
                )
                metric.add_metric(
                    labels=["queries_received_task_db_tables_upgrade_update_status"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['task_breakdown']['tables']['tasks']['upgrade_update_status']}"
                )
                metric.add_metric(
                    labels=["queries_received_wazuhdb"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['wazuhdb']}"
                )
                metric.add_metric(
                    labels=["queries_received_wazuhdb_remove"],
                    value=f"{daemon_metrics['queries']['received_breakdown']['wazuhdb_breakdown']['db']['remove']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_total"],
                    value=f"{daemon_metrics['time']['execution']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_total"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_begin"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['begin']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_close"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['close']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_commit"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['commit']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_remove"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['remove']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_sql"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_vacuum"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['vacuum']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_get_fragmentation"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['db']['get_fragmentation']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_ciscat"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['ciscat']['ciscat']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_rootcheck"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['rootcheck']['rootcheck']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_sca"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['sca']['sca']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_dbsync"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['sync']['dbsync']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscheck_fim_file"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['fim_file']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscheck_fim_registry"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['fim_registry']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscheck"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscheck']['syscheck']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_hotfixes"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_hotfixes']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_hwinfo"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_hwinfo']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_network_address"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_network_address']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_network_iface"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_network_iface']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_network_protocol"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_network_protocol']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_osinfo"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_osinfo']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_packages"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_packages']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_ports"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_ports']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_syscollector_processes"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['syscollector']['syscollector_processes']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_agent_db_table_vulnerability"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['agent_breakdown']['tables']['vulnerability']['vuln_cves']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_total"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_backup"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['db']['backup']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_sql"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_vacuum"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['db']['vacuum']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_get_fragmentation"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['db']['get_fragmentation']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_delete_agent"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['delete-agent']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_disconnect_agent"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['disconnect-agents']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_find_agent"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['find-agent']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_get_agent_info"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['get-agent-info']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_get_agents_by_conn_status"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['get-agents-by-connection-status']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_get_all_agents"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['get-all-agents']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_get_distinct_groups"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['get-distinct-groups']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_get_groups_integrity"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['get-groups-integrity']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_insert_agent"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['insert-agent']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_reset_agent_conn"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['reset-agents-connection']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_select_agent_group"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['select-agent-group']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_select_agent_name"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['select-agent-name']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_set_agent_groups"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['set-agent-groups']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_sync_agent_groups_get"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['sync-agent-groups-get']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_sync_agent_info_get"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['sync-agent-info-get']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_sync_agent_info_set"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['sync-agent-info-set']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_update_agent_data"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['update-agent-data']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_update_agent_name"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['update-agent-name']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_update_connection_status"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['update-connection-status']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_agent_update_keepalive"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['agent']['update-keepalive']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_belongs_get_group_agents"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['belongs']['get-group-agents']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_belongs_select_group_belong"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['belongs']['select-group-belong']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_group_delete_group"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['group']['delete-group']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_group_find_group"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['group']['find-group']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_group_insert_agent_group"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['group']['insert-agent-group']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_group_select_groups"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['group']['select-groups']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_global_db_tables_labels_get_labels"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['global_breakdown']['tables']['labels']['get-labels']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_mitre"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['mitre']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_mitre_db_sql"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['mitre_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_sql"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['db']['sql']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_delete_old"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['delete_old']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_set_timeout"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['set_timeout']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_upgrade"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['upgrade']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_upgrade_cancel_tasks"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['upgrade_cancel_tasks']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_upgrade_custom"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['upgrade_custom']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_upgrade_get_status"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['upgrade_get_status']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_upgrade_result"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['upgrade_result']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_task_db_tables_upgrade_update_status"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['task_breakdown']['tables']['tasks']['upgrade_update_status']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_wazuhdb"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['wazuhdb']}"
                )
                metric.add_metric(
                    labels=["db_exec_time_wazuhdb_remove"],
                    value=f"{daemon_metrics['time']['execution_breakdown']['wazuhdb_breakdown']['db']['remove']}"
                )
            else:
                unmonitored_daemons += 1
                metric = GaugeMetricFamily(
                    "unmonitored_wazuh_daemons",
                    "Daemons detected on manager without current metrics",
                    labels=["daemon"]
                )
                metric.add_metric(
                    labels=["name"],
                    value=str(unmonitored_daemons)
                )
            yield metric

if __name__ == "__main__":
    logger.info("Starting Wazuh prometheus exporter")
    start_http_server(int(listen_port))
    REGISTRY.register(WazuhCollector())

    while True:
        time.sleep(1)
