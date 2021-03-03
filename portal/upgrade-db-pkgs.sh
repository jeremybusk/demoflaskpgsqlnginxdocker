#!/bin/bash
# Allow remote or local users with sudo priv to update.
set -ex

app_user=demoportal
sudo -i -u ${app_user}  bash -c "source venv/bin/activate;
    pip3 install --upgrade .;
    export FLASK_APP=demoportal;
    source venv/bin/activate; flask db upgrade"
sudo systemctl restart $app_user 
