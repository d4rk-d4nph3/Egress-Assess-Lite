# Egress-Assess-Lite

Adapted from FortyNorthSecurity's [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)

Specially made to be assess exfiltration in Windows systems.

Supported clients are:
* FTP
* ICMP
* HTTPS
* DNS

## Deployment

```sh
pip install PyInstaller==3.6   # For python 2
pyinstaller --onefile Egress-Assess-Lite.py
```
