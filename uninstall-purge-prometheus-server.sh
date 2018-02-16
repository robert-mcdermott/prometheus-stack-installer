#!/bin/bash
#set -e

echo -e "\n!!!!!Warning!!!!!!"
echo -e "All Prometheus related services, configuration and data will be purged from this system in 30 seconds!"
echo -e "Hit ctrl-c (control-c) to abort if that is not your intention."
echo -e "!!!!!Warning!!!!!!\n"
sleep 30 

docker stop prometheus alertmanager pushgateway grafana > /dev/null
docker rm prometheus alertmanager pushgateway grafana > /dev/null
rm -rf /etc/prometheus
rm -rf /var/prometheus-data
rm -rf /var/alertmanager-data
rm -rf /var/pushgateway-data
rm -rf /var/grafana-data
rm -rf /etc/nginx/ssl
rm -rf /etc/nginx/creds
rm /etc/nginx/sites-enabled/prometheus.conf
rm /etc/nginx/sites-enabled/alertmanager.conf
rm /etc/nginx/sites-enabled/pushgateway.conf
rm /etc/nginx/sites-enabled/grafana.conf
ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
rm /etc/cron.d/purge-stale-push-metrics

echo -e "All prometheus containers, configuration and data have been purged from this system."
