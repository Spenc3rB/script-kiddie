# Scripts I've accumulated over the years

## Table of Contents
1. [Simple Updater](#1.-Simple-Updater)

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