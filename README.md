# Wazuh Prometheus exporter

Simple prometheus exporter for Wazuh server

## System environments

| Name                  | Description                                           |
|-----------------------|-------------------------------------------------------|
| WAZUH_API_HOST        | Wazuh API host IP address or hostname                 |
| WAZUH_API_PORT        | Wazuh API port e.g `55000`                            |
| WAZUH_API_USERNAME    | Wazuh API user for authorization                      |
| WAZUH_API_PASSWORD    | Wazuh API user password for authorization             |
| EXPORTER_PORT         | Exporter listen port, default 5000                    |


## Deployment

The solution can be run as docker container or inside Kubernetes

Building docker container (See Makefile for build details and other options)

```shell
make build

```


Example of a simple Kubernetes deployment

```shell
cd deployment

```

Change variables `WAZUH_API_HOST/WAZUH_API_PORT/WAZUH_API_USERNAME/WAZUH_API_PASSWORD`

And run kubectl command for example for wazuh namespace

```shell
kubectl apply -f deployment.yaml -n wazuh

```
