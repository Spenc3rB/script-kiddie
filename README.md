# Scripts I've accumulated over the years

## Table of Contents
1. [Simple Updater](#1.-Simple-Updater)
2. [j1708-rp1210.py](#2.-j1708-rp1210.py)

### 1. Simple Updater

Ever needed to automate the update process? Hate using large bulky update methods? This guy will sit perfectly in your systemd services for a github-based project. To start, download the script and make it executable:

```bash
wget https://raw.githubusercontent.com/Spenc3rB/script-kiddie/refs/heads/main/simple_updater
```
```
chmod +x simple_updater
```
Check it out:
```
./simple_updater <full-path-directory-to-monitor>
```
Then run it as a service:
```
echo "[Unit]
Description=Simple Updater
After=network.target

[Service]
ExecStart=<full-path-to-script>/simple_updater <full-path-directory-to-monitor>

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/simple_updater.service
```
```
echo "[Unit]
Description=Run Simple Updater at Midnight

[Timer]
OnCalendar=00:00  # Schedule (e.g., midnight)
Persistent=true    # Run even if the time was missed

[Install]
WantedBy=timers.target" | sudo tee /etc/systemd/system/simple_updater.timer
```
Then enable the service and timer:
```
sudo systemctl enable simple_updater.service
```
```
sudo systemctl start simple_updater.timer
```
Or use cron jobs ;)
```bash
crontab -e
```

Then add the following line:

```bash
0 0 * * * /full-path-to-script/simple_updater /full-path-directory-to-monitor
```

This cron job will run the script at midnight every day.

### 2. j1708-rp1210.py

This script is a simple Python-based J1708 to RP1210 bridge. It allows you to read J1708 messages and send them over an RP1210 interface. To use it, ensure you have Python installed and the required libraries:

```powershell
<32-bit Python> -m pip install "setuptools~=58.1.0"
<32-bit Python> -m pip install "jsbeautifier~=1.14.3"
<32-bit Python> -m pip install "PyYAML~=6.0"
<32-bit Python> -m pip install "tqdm~=4.62.3"
<32-bit Python> -m pip install "git+https://github.com/dfieschko/RP1210"
<32-bit Python> -m pip install "bitstring~=3.1.9"
<32-bit Python> -m pip install "scapy~=2.4.5"
```

Then install the script:

```powershell
wget https://raw.githubusercontent.com/Spenc3rB/script-kiddie/refs/heads/main/j1708-rp1210
```

and run it:

```powershell
python32 .\j1708-rp1210.py --help
usage: j1708-rp1210.py [-h] [--list] [--api API] [--device DEVICE] [--protocol PROTOCOL] [--timeout TIMEOUT] [--duration DURATION] [--count COUNT] [--filter-mid FILTER_MID]
                       [--filter-pid FILTER_PID] [--show-cs] [--checksum] [--echo] [--log LOG] [--send SEND [SEND ...]] [--auto-cs] [--send-interval SEND_INTERVAL] [--send-repeat SEND_REPEAT]


options:
  -h, --help            show this help message and exit
  --list                List APIs/devices/protocols and exit
  --api, --vendor API   RP1210 API name (e.g. DGDPA5, DGDPAXL, NULN2R32)
  --device DEVICE       Device ID (default: 1)
  --protocol PROTOCOL   Protocol string per driver (default: J1708)
  --timeout TIMEOUT     Per-read timeout seconds (<=0.255 recommended)
  --duration DURATION   Stop after N seconds
  --count COUNT         Stop after N frames
  --filter-mid FILTER_MID
                        Comma/space list of MIDs (e.g. 0x88 0x80)
  --filter-pid FILTER_PID
                        Comma/space list of PIDs (e.g. 0x9e 158)
  --show-cs             Print last byte separately as checksum
  --checksum            Ask driver to include checksum on read (depends on wrapper)
  --echo                Request echo of transmitted frames (if supported)
  --log LOG             Write received frames (hex) to this file
  --send SEND [SEND ...]
                        Bytes to TX (hex or dec). Max 21 bytes including checksum.
  --auto-cs             Append checksum for you (if you did not include it)       
  --send-interval SEND_INTERVAL
                        Interval between repeated sends in seconds
  --send-repeat SEND_REPEAT
                        Times to send the frame