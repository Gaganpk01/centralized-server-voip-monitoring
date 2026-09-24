# Centralized Server & VoIP Monitoring Platform

A centralized **monitoring and observability platform** designed to monitor Linux servers, infrastructure services, databases, VoIP services, applications, and logs across multiple client environments.

The platform combines **Prometheus, Grafana, Alertmanager, Loki, Promtail, exporters, and custom Bash monitoring scripts** to provide centralized metrics, dashboards, log monitoring, and automated alerts.

---

## 🏗️ Architecture

```text
                         ┌─────────────────────────┐
                         │        GitHub           │
                         │ Configs & Monitoring    │
                         │       Scripts           │
                         └────────────┬────────────┘
                                      │
                                      ▼
                  ┌────────────────────────────────────┐
                  │      Central Monitoring Server     │
                  │                                    │
                  │  Prometheus     Grafana            │
                  │  Alertmanager   Loki               │
                  └───────────────┬────────────────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
              ┌──────────┐  ┌──────────┐  ┌──────────┐
              │ Client 01│  │ Client 02│  │ Client 03│
              │          │  │          │  │          │
              │ Exporters│  │ Exporters│  │ Exporters│
              │ Promtail │  │ Promtail │  │ Promtail │
              │ Bash     │  │ Bash     │  │ Bash     │
              └──────────┘  └──────────┘  └──────────┘
```

### Monitoring Flow

```text
Client Servers
     │
     ├── Node Exporter
     ├── Nginx Exporter
     ├── MongoDB Exporter
     ├── Redis Exporter
     ├── Custom Bash Metrics
     │
     ▼
 Prometheus
     │
     ├──────────────► Grafana
     │
     └──────────────► Alertmanager
     
Client Logs
     │
     ▼
  Promtail
     │
     ▼
   Loki
     │
     ▼
  Grafana
```

---

## 🚀 Features

* Centralized Linux server monitoring
* CPU, memory, disk, network and system monitoring
* Nginx monitoring
* MongoDB monitoring
* Redis monitoring
* FreeSWITCH/VoIP monitoring
* SIP registration monitoring
* Active call monitoring
* Fail2Ban monitoring
* Monit service monitoring
* Custom application monitoring
* Custom Bash-based Prometheus metrics
* Node Exporter textfile collector integration
* Centralized log collection using Promtail
* Log aggregation using Loki
* Grafana dashboards
* Prometheus alert rules
* Alertmanager-based notifications
* Multi-server/client monitoring from a centralized server

---

## 🛠️ Technologies Used

| Technology       | Purpose                            |
| ---------------- | ---------------------------------- |
| Prometheus       | Metrics collection and monitoring  |
| Grafana          | Metrics and log visualization      |
| Alertmanager     | Alert management and notifications |
| Loki             | Centralized log aggregation        |
| Promtail         | Log collection from client servers |
| Node Exporter    | Linux system metrics               |
| Nginx Exporter   | Nginx metrics                      |
| MongoDB Exporter | MongoDB metrics                    |
| Redis Exporter   | Redis metrics                      |
| Bash             | Custom monitoring scripts          |
| Linux            | Server and service monitoring      |
| FreeSWITCH       | VoIP platform monitoring           |
| Fail2Ban         | Security/service monitoring        |
| Monit            | Process and service monitoring     |

---

## 📊 Monitoring Components

### Linux Server

Monitors:

* CPU utilization
* Memory utilization
* Disk usage
* Disk I/O
* Network traffic
* System load
* Swap usage
* Uptime
* System processes

### Nginx

Monitors Nginx availability and performance metrics through the Nginx exporter.

### MongoDB

Monitors database health and database-related metrics using the MongoDB exporter.

### Redis

Monitors Redis availability and performance metrics using the Redis exporter.

### FreeSWITCH / VoIP

Custom monitoring scripts are used to collect application-specific FreeSWITCH metrics such as:

```text
freeswitch_up
freeswitch_active_calls
freeswitch_sip_registrations
freeswitch_memory_bytes
freeswitch_memory_percent
```

These metrics are exposed to Prometheus through the **Node Exporter textfile collector**.

### Fail2Ban

Custom metrics provide visibility into:

* Jail status
* Banned IP addresses
* Service availability
* Security-related events

### Monit

Custom monitoring scripts collect service/process health information from Monit.

---

## 🧩 Custom Bash Monitoring

Not every application has a suitable Prometheus exporter.

To solve this, custom Bash scripts generate Prometheus-compatible metrics and expose them through the Node Exporter textfile collector.

Example:

```text
/var/lib/node_exporter/textfile_collector/
```

Example metric:

```text
freeswitch_up 1
```

Prometheus then scrapes these metrics along with standard exporter metrics.

---

## 📁 Repository Structure

```text
centralized-server-voip-monitoring/
│
├── README.md
│
├── prometheus/
│   ├── prometheus.yml
│   └── rules/
│       └── alerts.yml
│
├── alertmanager/
│   └── alertmanager.yml.example
│
├── grafana/
│   ├── dashboards/
│   │   └── server-monitoring.json
│   └── provisioning/
│
├── loki/
│   └── loki-config.yml
│
├── promtail/
│   └── promtail-config.yml
│
├── exporters/
│   ├── node-exporter/
│   ├── nginx/
│   ├── mongodb/
│   └── redis/
│
├── scripts/
│   ├── freeswitch_metrics.sh
│   ├── fail2ban_metrics.sh
│   ├── monit_metrics.sh
│   └── service_health.sh
│
├── systemd/
│   └── monitoring-services/
│
├── docs/
│   └── architecture.md
│
└── screenshots/
    ├── grafana-dashboard.png
    └── alerts.png
```

---

## 📈 Grafana Dashboard

The Grafana dashboard provides centralized visibility into server and application health.

---

## 🚨 Alerting

Prometheus evaluates configured alert rules and sends firing alerts to Alertmanager.

Alertmanager handles notification routing for events such as:

* Server down
* High CPU usage
* High memory usage
* High disk utilization
* Service unavailable
* FreeSWITCH unavailable
* Application/service failures
  
---

## 📝 Log Monitoring

Logs are collected from client servers using **Promtail** and sent to the centralized **Loki** server.

```text
Client Server
     │
     │ Logs
     ▼
 Promtail
     │
     ▼
   Loki
     │
     ▼
 Grafana
```

This provides centralized log searching and troubleshooting without requiring direct access to every client server.

---

## 🔐 Security

Sensitive production information is intentionally excluded from this repository.

The repository does not contain:

* Production passwords
* API keys
* SSH private keys
* SMTP credentials
* Client credentials
* Production IP addresses
* Customer-sensitive information

Example configuration files are provided where required.

---

## 🎯 Project Objectives

The main objectives of this project are:

1. Centralize monitoring of multiple Linux and VoIP environments.
2. Reduce dependency on manual server/service checks.
3. Provide real-time infrastructure and application visibility.
4. Centralize logs for easier troubleshooting.
5. Detect service failures automatically.
6. Provide automated notifications for critical events.
7. Support custom application metrics where standard exporters are unavailable.

---

## 🔮 Future Improvements

* Infrastructure deployment using Ansible
* Automated monitoring server provisioning
* Docker-based deployment
* Kubernetes monitoring
* AWS integration
* CI/CD pipeline for monitoring configuration
* Automated client onboarding
* Additional application-specific exporters

---

## 👨‍💻 Author

**Gagan Singh**

Cloud / DevOps Engineer

**Skills:** AWS | Linux | Docker | Kubernetes | Jenkins | Ansible | Prometheus | Grafana | Loki | Bash
