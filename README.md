# Wazuh Prometheus exporter

Simple prometheus exporter for Wazuh server

## System environments

| Name                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| WAZUH_API_HOST          | Wazuh API host e.g `127.0.0.1` or `wazuh`         |
| WAZUH_API_PORT          | Wazuh API port e.g `55000` |
| WAZUH_API_USERNAME      | Wazuh API user for authorization|
| WAZUH_API_PASSWORD      | Wazuh API user password for authorization|

## Deployment

The solution can be run as docker container or inside Kubernetes

Building docker container

```shell
docker build . -t wazuh-exporter:latest

```

or You can pull the existing image from DockerHub

```shell
docker pull kennyopennix/wazuh-exporter:latest
```

Example of Kubernetes deployment

```shell
cd deployment

```

Change variables `WAZUH_API_HOST/WAZUH_API_PORT/WAZUH_API_USERNAME/WAZUH_API_PASSWORD`

And run kubectl command for example for wazuh namespace

```shell
kubectl apply -f deployment.yaml -n wazuh

```
