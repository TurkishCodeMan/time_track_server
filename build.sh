#!/usr/bin/env bash
# Exit on error
set -o errexit

# Create logs directory
mkdir -p logs

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Install additional dependencies for ASGI
pip install uvicorn gunicorn

# Convert static asset files
python manage.py collectstatic --no-input

# Apply any outstanding database migrations
python manage.py migrate 