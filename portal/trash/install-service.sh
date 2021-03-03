#!/bin/bash
set -e

username=demoportal

if ! getent group ${username} >/dev/null; then
        addgroup --quiet --system ${username}
fi

if ! getent passwd ${username} >/dev/null; then
        adduser --system --ingroup ${username} \
            --home /var/lib/${username} ${username} \
            --gecos "${username} management daemon" \
            --disabled-login
        chown ${username}:${username} /var/lib/${username}
fi

sudo bash -c " cat > /lib/systemd/system/${username}.service <<EOF
[Unit]
Description=Demo Customer Portal 
Documentation=https://wiki.uvoo.io
After=network.target

[Service]
User=${username}
WorkingDirectory=/var/lib/${username}
ExecStart=gunicorn -w 4 -b 0.0.0.0:4000 demoportal:app 
Restart=on-failure

[Install]
WantedBy=multi-user.target
Alias=demoportal.service
EOF"
