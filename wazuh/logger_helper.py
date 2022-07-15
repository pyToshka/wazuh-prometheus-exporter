import os

import json_logging
import logging
import http.client

log_level = os.environ.get("EXPORTER_LOG_LEVEL", "INFO")
if log_level == "DEBUG":
    http.client.HTTPConnection.debuglevel = 1


def get_logger():
    """
    Utility function to get logger object
    :return:
    logger object
    """
    json_logging.init_non_web(enable_json=True)
    logger = logging.getLogger("wazuh-exporter")
    logging.basicConfig()
    json_logging.config_root_logger()
    logger.setLevel(log_level)
    logging.addLevelName(logging.ERROR, "error")
    logging.addLevelName(logging.CRITICAL, "critical")
    logging.addLevelName(logging.WARNING, "warning")
    logging.addLevelName(logging.INFO, "info")
    logging.addLevelName(logging.DEBUG, "debug")
    logger.addHandler(logging.NullHandler())
    return logger
