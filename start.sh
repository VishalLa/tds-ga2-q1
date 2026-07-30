#!/bin/bash
# Set this whole file as your Render "Start Command":
#   bash start.sh
set -e

bash setup_files.sh
exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"
