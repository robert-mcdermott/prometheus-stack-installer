#!/bin/bash
set -e

# Check to make sure this system is running Ubuntu 16.04
if [ -e /etc/os-release ]
then
    if grep -Fxq "VERSION_ID=\"16.04\"" /etc/os-release
    then
        echo -e "System running Ubuntu 16.04... Good!"
    else
        echo -e "Sorry! This script has only been tested on Ubuntu 16.04... ABORTING...." 
        exit 1
    fi
else
    echo -e "Sorry! This script has only been tested on Ubuntu 16.04... ABORTING...." 
    exit 1
fi

# Variables #################################
metric_retension=366d
metric_scrape_interval=1m
prometheus_ver=v2.0.0
alertmanager_ver=v0.10.0
pushgateway_ver=v0.4.0
grafana_ver=4.6.1
prometheus_hostname=<hostname>
prometheus_ext_port=443
prometheus_username=<username>
prometheus_password=<password>
grafana_hostname=${prometheus_hostname}
grafana_ext_port=3333
grafana_password=<password>
pushgateway_hostname=${prometheus_hostname}
pushgateway_ext_port=9991
pushgateway_username=<username>
pushgateway_password=<password>
alertmanager_hostname=${prometheus_hostname}
alertmanager_ext_port=9993
alertmanager_username=<username>
alertmanager_password=<password>
slackurl=https://hooks.slack.com/services/XZY
slackchannel=#prometheus-alerts
############################################

# Update packages and install nginx and docker
echo "Installing nginx and docker..."
apt-get update -qq
apt-get install -qq -y nginx docker.io python
service docker restart > /dev/null

# configure nginx
echo "Configuring nginx..."
mkdir -p /etc/nginx/ssl
mkdir -p /etc/nginx/creds

echo -e "\t->Installing SSL cert..."
cp -a nginx/ssl/cert.pem /etc/nginx/ssl/cert.pem
cp -a nginx/ssl/cert.key /etc/nginx/ssl/cert.key
echo -e "\t->Generating credentials..."
docker run -ti --rm httpd:2 htpasswd -bn ${prometheus_username} ${prometheus_password} > /etc/nginx/creds/prometheus 
docker run -ti --rm httpd:2 htpasswd -bn ${alertmanager_username} ${alertmanager_password} > /etc/nginx/creds/alertmanager 
docker run -ti --rm httpd:2 htpasswd -bn ${pushgateway_username} ${pushgateway_password} > /etc/nginx/creds/pushgateway
chown root:www-data /etc/nginx/ssl/cert.key
chmod 600 /etc/nginx/ssl/cert.key
rm /etc/nginx/sites-enabled/default

echo -e "\t->Setting up Grafana proxy..."
cat > /etc/nginx/sites-enabled/grafana.conf << EOL
server {
    listen ${grafana_ext_port};
    server_name ${grafana_hostname};
    ssl on;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/cert.key;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers "HIGH:!aNULL:!MD5 or HIGH:!aNULL:!MD5:!3DES";
    ssl_prefer_server_ciphers on;

    # Enable GZip Compression
    gzip on;
    gzip_http_version 1.1;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_proxied any;
    gzip_types text/plain text/html text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript text/x-js image/x-icon; gzip_buffers 16 8k;
    gzip_disable "MSIE [1-6]\.(?!.*SV1)";

    location / {

      proxy_set_header        Host \$host:\$server_port;
      proxy_set_header        X-Real-IP \$remote_addr;
      proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto \$scheme;
      proxy_pass          http://127.0.0.1:3000;
      proxy_read_timeout  90;
    }
}
EOL

echo -e "\t->Setting up Prometheus proxy..."
cat > /etc/nginx/sites-enabled/prometheus.conf << EOL
server {
    listen ${prometheus_ext_port};
    server_name ${prometheus_hostname};
    ssl on;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/cert.key;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers "HIGH:!aNULL:!MD5 or HIGH:!aNULL:!MD5:!3DES";
    ssl_prefer_server_ciphers on;

    # Enable GZip Compression
    gzip on;
    gzip_http_version 1.1;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_proxied any;
    gzip_types text/plain text/html text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript text/x-js image/x-icon; gzip_buffers 16 8k;
    gzip_disable "MSIE [1-6]\.(?!.*SV1)";

    location / {

      proxy_set_header        Host \$host:\$server_port;
      proxy_set_header        X-Real-IP \$remote_addr;
      proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto \$scheme;
      proxy_pass          http://127.0.0.1:9090;
      proxy_read_timeout  90;
      auth_basic "Prometheus";
      auth_basic_user_file "/etc/nginx/creds/prometheus";
    }
}
EOL

echo -e "\t->Setting up Pushgateway proxy..."
cat > /etc/nginx/sites-enabled/pushgateway.conf << EOL
server {
    listen ${pushgateway_ext_port};
    server_name ${pushgateway_hostname};
    ssl on;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/cert.key;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers "HIGH:!aNULL:!MD5 or HIGH:!aNULL:!MD5:!3DES";
    ssl_prefer_server_ciphers on;

    # Enable GZip Compression
    gzip on;
    gzip_http_version 1.1;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_proxied any;
    gzip_types text/plain text/html text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript text/x-js image/x-icon; gzip_buffers 16 8k;
    gzip_disable "MSIE [1-6]\.(?!.*SV1)";

    location / {

      proxy_set_header        Host \$host:\$server_port;
      proxy_set_header        X-Real-IP \$remote_addr;
      proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto \$scheme;
      proxy_pass          http://127.0.0.1:9091;
      proxy_read_timeout  90;
      auth_basic "Prometheus";
      auth_basic_user_file "/etc/nginx/creds/pushgateway";
    }
}
EOL

echo -e "\t->Setting up Alertmanager proxy..."
cat > /etc/nginx/sites-enabled/alertmanager.conf << EOL
server {
    listen ${alertmanager_ext_port};
    server_name ${alertmanager_hostname};
    ssl on;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/cert.key;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers "HIGH:!aNULL:!MD5 or HIGH:!aNULL:!MD5:!3DES";
    ssl_prefer_server_ciphers on;

    # Enable GZip Compression
    gzip on;
    gzip_http_version 1.1;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_proxied any;
    gzip_types text/plain text/html text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript text/x-js image/x-icon; gzip_buffers 16 8k;
    gzip_disable "MSIE [1-6]\.(?!.*SV1)";

    location / {

      proxy_set_header        Host \$host:\$server_port;
      proxy_set_header        X-Real-IP \$remote_addr;
      proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto \$scheme;
      proxy_pass          http://127.0.0.1:9093;
      proxy_read_timeout  90;
      auth_basic "Prometheus";
      auth_basic_user_file "/etc/nginx/creds/alertmanager";
    }
}
EOL


echo -e "\t->Restarting Nginx..."
service nginx restart

# Setup Pushgateway
echo -e "Configuring and starting Pushgateway..."
mkdir -p /var/pushgateway-data
chmod 777 /var/pushgateway-data
docker pull prom/pushgateway:${pushgateway_ver} > /dev/null
docker run -d --restart=always -p 127.0.0.1:9091:9091 --name pushgateway -v /var/pushgateway-data:/pushgateway prom/pushgateway:${pushgateway_ver} -persistence.file /pushgateway/push.data > /dev/null


# Setup Prometheus 
echo -e "Configuring and starting Prometheus..."
mkdir -p /etc/prometheus
mkdir -p /etc/prometheus/discovered
mkdir -p /var/prometheus-data
chmod 777 /var/prometheus-data
docker pull prom/prometheus:${prometheus_ver} > /dev/null

cat > /etc/prometheus/prometheus.yml << EOL
# Global config
global:
  scrape_interval:     ${metric_scrape_interval} 
  evaluation_interval: ${metric_scrape_interval} 

# Alertmanager configuration
alerting:
  alertmanagers:
  - static_configs:
    - targets:
      - ${alertmanager_hostname}:${alertmanager_ext_port}
    scheme: https
    basic_auth:
      username: '${alertmanager_username}'
      password: '${alertmanager_password}'
    tls_config:
      insecure_skip_verify: true 
    timeout: 10s

# Alert rules
rule_files:
  - "rules.yml"

# Scrape configs 
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'pushgateway'
    scrape_interval: 1m
    scheme: https
    basic_auth:
      username: '${pushgateway_username}'
      password: '${pushgateway_password}'
    tls_config:
      insecure_skip_verify: true
    honor_labels: true
    static_configs:
      - targets:
        - ${pushgateway_hostname}:${pushgateway_ext_port} 

  - job_name: 'discovered'
    file_sd_configs:
      - files: ['/etc/prometheus/discovered/*.yml']

EOL

cat > /etc/prometheus/rules.yml << EOL
groups:
- name: servers
  rules:
  - alert: node_down
    expr: up == 0
    labels:
      severity: critical
      value: '{{\$value}}'

  - alert: high_load_warning
    expr: node_load1 > 10.0
    labels:
      severity: warning
      value: '{{\$value}}'
    annotations:
      description: '{{ \$labels.instance }} of job {{ \$labels.job }} at moderately high load level.'
      summary: Instance {{ \$labels.instance }} at moderately high load level.

  - alert: high_load_critical
    expr: node_load1 > 20.0
    labels:
      severity: critical
      value: '{{\$value}}'
    annotations:
      description: '{{ \$labels.instance }} of job {{ \$labels.job }} at critically high load level.'
      summary: Instance {{ \$labels.instance }} at critically high load level.
EOL

docker run -d --restart=always -p 127.0.0.1:9090:9090 --name prometheus -v /var/prometheus-data:/prometheus -v /etc/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml -v /etc/prometheus/rules.yml:/etc/prometheus/rules.yml -v /etc/prometheus/discovered:/etc/prometheus/discovered prom/prometheus:${prometheus_ver} --storage.tsdb.retention=${metric_retension} --config.file=/etc/prometheus/prometheus.yml --web.enable-admin-api > /dev/null

# Alert Manager Setup
echo -e "Configuring and starting Alertmanager..."
mkdir -p /etc/prometheus/alertmanager
mkdir -p /etc/prometheus/alertmanager/templates
mkdir -p /var/alertmanager-data
docker pull prom/alertmanager:${alertmanager_ver} > /dev/null 

cat > /etc/prometheus/alertmanager/config.yml << EOL
route:
    receiver: 'slack'
    group_by: [alertname, job]
    #repeat_interval: 1h

receivers:
    - name: 'slack'
      slack_configs:
          - send_resolved: true
            title: '{{ template "slack.fh.title" . }}'
            pretext: '{{ template "slack.default.pretext" . }}'
            text: '{{ template "slack.default.text" . }}'
            fallback: '{{ template "slack.default.fallback" . }}'
            username: 'Prometheus'
            channel: '${slackchannel}'
            api_url: ${slackurl} 
templates:
  - '/etc/alertmanager/templates/default.tmpl'
EOL

cat > /etc/prometheus/alertmanager/templates/default.tmpl << EOL
{{ define "__alertmanagerURL" }}https://${alertmanager_hostname}:$alertmanager_ext_port{{ end }}
{{ define "__subject" }}[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .GroupLabels.SortedPairs.Values | join " " }} {{ if gt (len .CommonLabels) (len .GroupLabels) }}({{ with .CommonLabels.Remove .GroupLabels.Names }}{{ .Values | join " " }}{{ end }}){{ end }}{{ end }}
{{ define "slack.fh.title" }}{{ template "__subject" . }}{{ end }}
{{ define "slack.fh.fallback" }}{{ template "slack.fh.title" . }} | {{ template "slack.fh.titlelink" . }}{{ end }}
{{ define "slack.fh.titlelink" }}{{ template "__alertmanagerURL" . }}{{ end }}
EOL

docker run -d --restart=always -p 127.0.0.1:9093:9093 --name alertmanager -v /var/alertmanager-data:/alertmanager -v /etc/prometheus/alertmanager:/etc/alertmanager prom/alertmanager:${alertmanager_ver} > /dev/null


# Setup Grafana 
echo -e "Configuring and starting Grafana..."
mkdir -p /var/grafana-data
mkdir -p /etc/prometheus
mkdir -p /etc/prometheus/grafana
chmod 777 /var/grafana-data
docker pull grafana/grafana:${grafana_ver} > /dev/null
docker run -it --rm --entrypoint=/bin/cat grafana/grafana:${grafana_ver} /etc/grafana/grafana.ini > /etc/prometheus/grafana/grafana.ini
docker run -it --rm --entrypoint=/bin/cat grafana/grafana:${grafana_ver} /etc/grafana/ldap.toml > /etc/prometheus/grafana/ldap.toml
docker run -d --restart=always -p 127.0.0.1:3000:3000 --name=grafana -v /var/grafana-data:/var/lib/grafana -v /etc/prometheus/grafana:/etc/grafana -e "GF_SECURITY_ADMIN_PASSWORD=${grafana_password}" -e "GF_DEFAULT_INSTANCE_NAME=${grafana_hostname}" -e "GF_SERVER_ROOT_URL=https://${granfana_hostname}:${grafana_ext_port}" grafana/grafana:${grafana_ver} > /dev/null

# Setup script and cron job to purge stale push metrics
echo -e "Installing pushgateway stale metric purge script and cronjob..."
cat > /etc/prometheus/purge-stale-push-metrics.py << EOL
#!/usr/bin/python
import urllib2
import time
import os
import re

# URL of the push server metrics page
url = 'http://127.0.0.1:9091/metrics'

# format of metric below:
#push_time_seconds{instance="server4",job="some_job"} 1.5105289846299572e+09

res = urllib2.urlopen(url)
metrics = res.readlines()
for met in metrics:
    if met.startswith("push_time_seconds"):
        ts = float(met.strip().split()[-1])
        age = time.time() - ts
        if age > 1800:
            try:
                mi = re.match(r'.*instance="(\S+?)".*', met)
                instance = mi.group(1)
                mj = re.match(r'.*job="(\S+?)".*', met)
                job = mj.group(1)
                deleteurl = "%s/job/%s/instance/%s" % (url, job, instance)
                request = urllib2.Request(deleteurl)
                request.get_method = lambda: 'DELETE'
                urllib2.urlopen(request)
                # example of how do delete metric with curl:
                #print("curl -X DELETE http://127.0.0.1:9091/metrics/job/%s/instance/%s" % (job, instance))
            except:
                continue
EOL

chmod 755 /etc/prometheus/purge-stale-push-metrics.py

cat > /etc/cron.d/purge-stale-push-metrics << EOL
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/30 * * * * root /etc/prometheus/purge-stale-push-metrics.py >/dev/null 2>&1
EOL

echo -e "\nDone!\n"
docker ps

echo -e "\nHere are the URLs and credentials and details of each service:"
echo -e "\n---PROMETHEUS---"
echo -e "URL:      https://${prometheus_hostname}:${prometheus_ext_port}"
echo -e "Username: ${prometheus_username}"
echo -e "Password: ${prometheus_password}"
echo -e "Static Configuration: /etc/prometheus/prometheus.yml"
echo -e "Discovered Configuration: /etc/prometheus/discovered/*"
echo -e "Alert Rules: /etc/prometheus/rules.yml"
echo -e "Persistent Data: /var/prometheus-data"
echo -e "Service Restart Command: docker restart prometheus"

echo -e "\n---PUSHGATEWAY---"
echo -e "URL:      https://${pushgateway_hostname}:${pushgateway_ext_port}"
echo -e "Username: ${pushgateway_username}"
echo -e "Password: ${pushgateway_password}"
echo -e "Persistent Data: /var/pushgateway-data"
echo -e "Service Restart Command: docker restart pushgateway"

echo -e "\n---ALERTMANAGER---"
echo -e "URL:      https://${alertmanager_hostname}:${alertmanager_ext_port}"
echo -e "Username: ${alertmanager_username}"
echo -e "Password: ${alertmanager_password}"
echo -e "Configuration: /etc/prometheus/alertmanager/config.yml"
echo -e "Templates: /etc/prometheus/alertmanater/templates/*"
echo -e "Persistent Data: /var/alertmanager-data"
echo -e "Service Restart Command: docker restart altermanager"

echo -e "\n---GRAFANA---"
echo -e "URL:      https://${grafana_hostname}:${grafana_ext_port}"
echo -e "Username: admin"
echo -e "Password: ${grafana_password}"
echo -e "Configuration: /etc/prometheus/grafana/*"
echo -e "Persistent Data: /var/grafana-data"
echo -e "Service Restart Command: docker restart grafana"
