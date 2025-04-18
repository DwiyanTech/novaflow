
# Novaflow

Novaflow is a cutting-edge virtual server-based Web Application Firewall (WAF) solution. Powered by asynchronous processing and the Tokio threading framework, Novaflow effortlessly manages large volumes of traffic while maintaining exceptional performance. What sets it apart is its ability to detect and mitigate web-based attacks in real-time, meticulously adhering to predefined security rules, ensuring robust protection for your digital infrastructure.

## Current state
This tools is currently beta version (still need development new feature) but the main function is already done, need some feature like alert and traffic logging, custom arguments, healthcheck, reverse proxy, and dashboards

## How to run
Define the configuration `config.yaml` and `policy.yaml`
- `config.yaml` : VirtualServer configuration and listener configuration
```
listen_address: "0.0.0.0"
listen_port: 9000
ssl:
  enabled: true
  ca_path: "/path/to/ca.pem"
  key_path: "/path/to/key.pem"
logging:
  mode: "file"
  trace_traffic: true
  file_path: "/var/log/"
  file_name: "novaflow.log"
domain_server:
  enabled: true
  config:
    - name: domain_1
      domain_name: dwiyantech.com
      remote_address: "http://10.66.66.6"
virtual_server:
  enabled: true
  config:
    - name: Backend App 1
      path: /backend1
      remote_address: "http://example.com"
    - name: Backend App 2 # dd
      path: /backend2
      remote_address: "http://0.0.0.0:3001"
```
- `policy.yaml` : WAF rules with Rust Regex Match
```
policy_block:
 - policy_id: 1001 # policy id
   name: "XSS Attack # Rule name
   pattern: ".*script.*" # Regex match rules to block
   option: #  option for what request to check
    header: true # check header
    body: true # check body
    uri: true # check uri
 - policy_id: 1002
   name: "SQL Union Injection"
   pattern: "UniOn"
   option:
    header: true
    body: true
    uri: true

```
then run it into same folder in binary files 

## Screenshots
Screenshots: 
![](https://raw.githubusercontent.com/DwiyanTech/novaflow/refs/heads/main/screenshot/ss_1.png)
![](https://raw.githubusercontent.com/DwiyanTech/novaflow/refs/heads/main/screenshot/ss_3.png)
![](https://raw.githubusercontent.com/DwiyanTech/novaflow/refs/heads/main/screenshot/ss_2.png)