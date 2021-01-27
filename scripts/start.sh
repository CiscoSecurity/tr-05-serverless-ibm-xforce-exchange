#! /usr/bin/env sh
echo " .:|:.:|:. "
echo " C I S C O "
echo
echo " Integration Module: " `jq -r .NAME /app/container_settings.json`
echo "            Version: " `jq -r .VERSION /app/container_settings.json`
echo "         Secret Key: " `jq -r .SECRET_KEY /app/container_settings.json`
echo
echo "Starting supervisord ..."
echo
set -e
exec /usr/bin/supervisord -c /supervisord.ini
