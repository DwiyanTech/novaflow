
# Novaflow

Novaflow is a cutting-edge virtual server-based Web Application Firewall (WAF) solution. Powered by asynchronous processing and the Tokio threading framework, Novaflow effortlessly manages large volumes of traffic while maintaining exceptional performance. What sets it apart is its ability to detect and mitigate web-based attacks in real-time, meticulously adhering to predefined security rules, ensuring robust protection for your digital infrastructure.

## Current state
This tools is currently beta version (still need development new feature) but the main function is already done, need some feature like alert and traffic logging, custom arguments, healthcheck, reverse proxy, and dashboards


## List All Available Commands
```bash
Usage: novaflow [OPTIONS]

Options:
  -c, --config <CONFIG>  [default: config.yaml]
  -p, --policy <POLICY>  [default: policy.yaml]
  -h, --help             Print help
  -V, --version          Print version
```
## Features

- Support TLS
- Regex Support
- Domain Based configuration
- Virtual Server Based configuration
- Healthcheck


## List Example Configurations
Novaflow appears to be a Web Application Firewall (WAF) solution that is distributed as a single binary, simplifying its deployment and operation, here for all available arguments below :
```yaml
listen_address: "0.0.0.0"
listen_port: 9000
ssl:
  enabled: true
  ca_path: "example/sample.pem"
  key_path: "example/sample.rsa"
logging:
  mode: "stdout"
  trace_traffic: true
  file_path: ""
  file_name: ""
domain_server:
  enabled: true
  config:
    - name: domain_1
      domain_name: testserver.com
      remote_address: "http://1.1.1.1"
virtual_server:
  enabled: true
  config:
    - name: "Backend1"
      path: /backend1
      remote_address: "https://www.example.com/"
```
For complete guide see under example folder


## Run Locally

Download binary then mapped into configuration files (see example folder)
```bash
novaflow -c ./example/config.yaml -p ./example/policy.yaml
```


## Roadmap

- Add output to file feature

- Add Logging configuration more flexible

- Seperate Alerts and Block policy rules

- Run with many 2 or more policy files 

- Add docs site