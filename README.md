# AnyTLS-Manager  

[![Top Language](https://img.shields.io/github/languages/top/Kismet0123/AnyTLS-Manager.svg)](https://github.com/Kismet0123/AnyTLS-Manager)  

An AnyTLS management script supporting one-click installation, upgrade, and uninstallation  

> AnyTLS is a TLS proxy protocol designed to mitigate the "TLS in TLS" issue (featuring flexible packet splitting & padding strategies, connection multiplexing, reduced proxy latency, and concise configuration)  

> [!IMPORTANT]  
> The AnyTLS protocol is relatively new and currently only supported by Mihomo and Singbox  

---  

## Quick Start 📃  

**One-click deployment command**  

```bash  
#wget -O AnyTLS_Manager.sh --no-check-certificate https://raw.githubusercontent.com/Kismet0123/AnyTLS-Manager/refs/heads/main/AnyTLS_Manager.sh && chmod +x #AnyTLS_Manager.sh && ./AnyTLS_Manager.sh

wget -O AnyTLS_Manager.sh --no-check-certificate https://raw.githubusercontent.com/exxojay/AnyTLS-Manager/refs/heads/main/AnyTLS_Manager.sh && chmod +x AnyTLS_Manager.sh && ./AnyTLS_Manager.sh  
```  

**View logs**  

```
journalctl -u anytls
```

**Delete script**  

```
rm AnyTLS_Manager.sh
```

## Client Configuration Reference 🖥️  

### Mihomo Configuration Example (since mihomo 1.19.3)  

```yaml
proxies:  
- name: anytls  
  type: anytls  
  server: 1.2.3.4  
  port: 443  
  password: "<your password>"  
  client-fingerprint: chrome  
  udp: true  
  idle-session-check-interval: 30  
  idle-session-timeout: 30  
  min-idle-session: 0  
  sni: "example.com"  
  alpn:  
    - h2  
    - http/1.1  
  skip-cert-verify: true  
```  

### Singbox Configuration Example (since sing-box 1.12.0)  

```json
{  
  "type": "anytls",  
  "tag": "anytls-out",  
  "server": "127.0.0.1",  
  "server_port": 1080,  
  "password": "8JCsPssfgS8tiRwiMlhARg==",  
  "idle_session_check_interval": "30s",  
  "idle_session_timeout": "30s",  
  "min_idle_session": 5,  
  "tls": {},  

  ... // Dial fields  
}  
```  

# References 📚  

## [AnyTLS Original Repository](https://github.com/anytls/anytls-go)  

## [AnyTLS Official FAQ](https://github.com/anytls/anytls-go/blob/main/docs/faq.md)  

## [AnyTLS Protocol Documentation](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)  
