#!/bin/bash
set -e

# username="demoportal"

# ./deploy-files.sh
sudo apt-get install -y pkg-config libsystemd-dev libsystemd-dev libpq-dev python3-dev postgresql curl jq
./create-db.sh
# ./install-service.sh
# sudo su - "${username}"
flask db init
flask db migrate
flask db upgrade
# systemctl enable "${username}" 
# systemctl start "${username}" 
