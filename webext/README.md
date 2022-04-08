# TLS Stapling experiment

## Setup
Install the self-signed root certificate in firefox: Preferences -> Privacy & Security -> View Certificates -> Import `cert-fpki.pem`

## Start Experiment
```shell
for x in {1..1001}; do web-ext run -p /home/cyrill/.mozilla/firefox/1h9k7gh8.default-release/ -f /usr/bin/firefox --keep-profile-changes; done
```
