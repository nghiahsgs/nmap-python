# nmap-python
nmap python

```
sudo apt-get install nmap
pip install python-nmap
```

```
import nmap
scan1 = nmap.PortScanner()
scan1.scan('80.208.230.68', '1000-9999')
```

```
scan1.scaninfo()
scan1.all_hosts()
```

```
nmScan['127.0.0.1'].hostname()
'localhost'

>>> nmScan['127.0.0.1'].state()
'up'

>>> nmScan['127.0.0.1'].all_protocols()
['tcp']

>>> nmScan['127.0.0.1']['tcp'].keys()
[80, 25, 443, 22, 111]

>>> nmScan['127.0.0.1'].has_tcp(22)
```

```
nmScan['127.0.0.1']['tcp'][22]
```
