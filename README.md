# Prometheus Server Stack Installer 

This repository contains scripts to automate the installation and base configuration of the following services on a single host:

- Prometheus Server: https://github.com/prometheus/prometheus
- Pushgateway Server: https://github.com/prometheus/pushgateway
- Alertmanager Server: https://github.com/prometheus/alertmanager
- Grafana Server: https://github.com/grafana/grafana

All of the above services are running in docker containers to keep the system clean and allow easy upgrades. All data and configurtion is persisted outside of the containers in the host filesystem to make upgrades/rollbacks very simple. 

### Requirements

This script as only been tested on Ubuntu 16.04. The included SSL certificate and key is a self-signed cert, so you should replace it with your own valid certs to avoid SSL name mismatch warnings.

### Security

By default none of these services are SSL enabled, so this script will proxy all communication via an SSL enabled Nginx proxy that will be automatically installed and configured. Also, Prometheus, Alertmanager and the Pushgateway have no concept of users, so the Nginx proxy is providing authentication to protect these services.


### Downloading

Just clone this repository to the sysetem that you'll be installing Prometheus on:

```
git clone https://github.com/FredHutch/prometheus-stack-installer.git 
cd prometheus-stack-installer
```

### Installer Configuration

Edit the "Variables" section in the "install-prometheus-server.sh" script and provide at the bare minimum the prometheus hostname and your desired username and password for each service. You can optionally change the versions, metric retention period, global scrape interval, individual service hostnames (you'll need a CNAME pointing to this host for each), the external ports that will expose the services on and a Slack team/channel that you want to send alerts to. If you want to run multiple services on the default HTTPS port (443) then they must use different hostnames (need to create a CNAME for each). 

```
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
```

### Installing the Prometheus/Grafana Stack

To install the Prometheus stack run the following command from the downloaded repository:

```bash
bash install install-prometheus-server.sh
```

The above command will have output similar to the following. The tail end of the script output will provide you with the URLs, credentials and location of the configuraiton files.

```
System running Ubuntu 16.04... Good!
Installing nginx and docker...
Configuring nginx...
	->Installing SSL cert...
	->Generating credentials...
	->Setting up Grafana proxy...
	->Setting up Prometheus proxy...
	->Setting up Pushgateway proxy...
	->Setting up Alertmanager proxy...
	->Restarting Nginx...
Configuring and starting Pushgateway...
Configuring and starting Prometheus...
Configuring and starting Alertmanager...
Configuring and starting Grafana...
Installing pushgateway stale metric purge script and cronjob...

Done!

CONTAINER ID        IMAGE                       COMMAND                  CREATED             STATUS                  PORTS                      NAMES
4f9f987bb996        grafana/grafana:4.6.1       "/run.sh"                1 second ago        Up Less than a second   127.0.0.1:3000->3000/tcp   grafana
c6d69f121d0f        prom/alertmanager:v0.10.0   "/bin/alertmanager..."   2 seconds ago       Up 1 second             127.0.0.1:9093->9093/tcp   alertmanager
0eddc6725394        prom/prometheus:v2.0.0      "/bin/prometheus -..."   3 seconds ago       Up 2 seconds            127.0.0.1:9090->9090/tcp   prometheus
0d80070264d2        prom/pushgateway:v0.4.0     "/bin/pushgateway ..."   5 seconds ago       Up 4 seconds            127.0.0.1:9091->9091/tcp   pushgateway

Here are the URLs and credentials and details of each service:

---PROMETHEUS---
URL:      https://prom.fredhutch.org:3333
Username: user
Password: pass
Static Configuration: /etc/prometheus/prometheus.yml
Discovered Configuration: /etc/prometheus/discovered/*
Alert Rules: /etc/prometheus/rules.yml
Persistent Data: /var/prometheus-data
Service Restart Command: docker restart prometheus

---PUSHGATEWAY---
URL:      https://prom.fredhutch.org:9991
Username: user
Password: pass
Persistent Data: /var/pushgateway-data
Service Restart Command: docker restart pushgateway

---ALERTMANAGER---
URL:      https://prom.fredhutch.org:9993
Username: user
Password: pass
Configuration: /etc/prometheus/alertmanager/config.yml
Templates: /etc/prometheus/alertmanater/templates/*
Persistent Data: /var/alertmanager-data
Service Restart Command: docker restart altermanager

---GRAFANA---
URL:      https://prom.fredhutch.org:443
Username: admin
Password: pass
Configuration: /etc/prometheus/grafana/*
Persistent Data: /var/grafana-data
Service Restart Command: docker restart grafana

```

### Configuring the System

The configuraions provided are just the base or example configuration. You'll want to add scrape targets and alerting rules to Prometheus, notification rules to the Alertmanager.

- Prometheus:
  - Global settings and scrape configurations: /etc/prometheus/prometheus.yml
  - Alert rules: /etc/prometheus/rules.yml 
  - File based target discovery: /etc/prometheus/discovered/*.yml
  - Restart command: docker retart prometheus
- Alertmanager:
  - Alert notification rules: /etc/prometheus/alertmanager/config.yml 
  - restart command: docker retart alertmanager 
- Pushgateway:
  - no configuration needed, just a temporay metric cache 
- Grafana:
  - /etc/prometheus/grafana/grafana.ini 
  - /etc/prometheus/grafana/ldap.toml 
  - restart command: docker retart alertmanager 


### Uninstalling/purging the Prometeus/Grafana stack from your system 

To stop, remove all services and purge all configuration and data from your system, run the following command:

```bash
bash uninstall-purge-prometheus-server.sh
```

Becareful with this command as any configration changes and metric data will be permently lost. After running the uninstall-purge script, you'll be given 30 seconds to reconcider you actions and abort by hitting crtl-c (control-c). The output of this script looks like the following:

```
!!!!!Warning!!!!!!
All Prometheus related services, configuration and data will be purged from this system in 30 seconds!
Hit ctrl-c (control-c) to abort if that is not your intention.
!!!!!Warning!!!!!!

All prometheus containers, configuration and data have been purged from this system.
```

