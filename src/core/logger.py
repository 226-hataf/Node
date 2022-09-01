import ast
import logging
import os

LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')


FORMAT = '%(asctime)s %(clientip)-15s %(user)-8s %(message)s'

log = logging.getLogger("ZK_FLOW_ENGINE")
log.setLevel(getattr(logging, LEVEL))

# Define format for logs
fmt = '%(asctime)s | %(levelname)8s | %(message)s'

# Create stdout handler for logging to the console (logs all five levels)
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.DEBUG)

log.addHandler(stdout_handler)
