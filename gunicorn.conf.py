"""Gunicorn production configuration for VAEL."""
import os

bind = "0.0.0.0:8000"
workers = int(os.environ.get("VAEL_WORKERS", "2"))
worker_class = "uvicorn.workers.UvicornWorker"

# Use /dev/shm for worker heartbeat files — faster on Linux
worker_tmp_dir = "/dev/shm"

# Pipeline runs can take up to 60s; give headroom for slow networks
timeout = 120
graceful_timeout = 30
keepalive = 5

# Log to stdout/stderr for container log collection
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "warning").lower()

# Forward X-Forwarded-For from nginx
forwarded_allow_ips = "*"
proxy_allow_from = "*"
