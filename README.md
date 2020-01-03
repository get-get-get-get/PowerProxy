# PowerProxy
PowerShell SOCKS proxy with reverse proxy capabilities.

PowerProxy is written with penetration testers in mind. Reverse proxy functionality is a priority, for traversing networks that block inbound connections. Reverse proxy connections are encrypted by default. Username/Password authentication is supported for Socks 5 connections.

## Setup
Import the script as a module:

```powershell
Import-Module \\192.168.0.22\Public\PowerProxy.ps1
```

Optionally, create your own certificate for the reverse proxy handler:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out cert.pem

# If you want to verify the cert's fingerprint when connecting from powershell:
openssl x509 -in cert.pem -noout -sha1 -fingerprint | cut -d "=" -f 2 | tr -d ":"
```

## Usage

### **Run a reverse proxy**
On local machine, start the handler:
```bash
# Listen for reverse proxies on port 8080. Clients connect to port 1080
./reverse_proxy_handler.py -p 8080 --client-port 1080
```

In PowerShell:
```powershell
Start-ReverseSocksProxy 172.1.1.20 -Port 8080
```
Proxy clients can treat the server created by reverse_proxy_handler.py as if it were the actual SOCKS server:
```bash
curl --socks4 127.0.0.1:1080 http://10.10.2.69/
```

### **Run a traditional SOCKS server** 
```powershell
Start-SocksProxy Start-SocksProxy 172.10.2.20 -Port 9050
```

### Require authentication
Use PSCredential objects to require a username and password:
```powershell
# Create the credential
$Password = ConvertTo-SecureString -AsPlaintext -Force "Pa$$w0rd123"
$Cred = New-Object System.Management.Automation.PSCredential ("ProxyUser", $Password)

Start-ReverseSocksProxy -Credential $Cred -Address 10.10.10.24 -Verbose
```

## Limitations

- At the moment, only CONNECT requests are supported. BIND support is a goal, if practical.
- GSSAPI authentication is not supported.
- reverse_proxy_handler.py is only tested on UNIX-based machines, and probably doesn't work on Windows.