import logging
import os

LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')


FORMAT = '%(asctime)s %(clientip)-15s %(user)-8s %(message)s'

log = logging.getLogger("ZK_FLOW_ENGINE")
log.setLevel(eval(f"logging.{LEVEL}"))
