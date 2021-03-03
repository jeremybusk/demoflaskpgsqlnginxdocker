#!/usr/bin/env bash
# run this via "source prep-env.sh"

db_name="demoportal"
db_user="demoportal"
db_pass="demoportal"
export PGPASSWORD=${db_pass}

sudo apt-get install -y pkg-config libsystemd-dev libsystemd-dev libpq-dev python3-dev postgresql curl jq
# postgresql-server-dev-11
deactivate
rm -rf *.egg-info __pycache__/ venv || true
python3 -m venv venv
source venv/bin/activate
pip3 install -U pip wheel
# pip3 install -U -r requirements.txt
pip3 install -e .  # remove -e (editable) if not dev environment or unwanted.

# Create database user & database.
./create-db.sh
# ./create-db.sh drop  # Adding drop will drop user & database first

# Run database migrations.
export FLASK_APP=demoportal
export FLASK_ENV=development
export SQLALCHEMY_TRACK_MODIFICATIONS=True
export FLASK_RUN_PORT=4000
# flask db init  # Only run on initial
# flask db migrate  # Only use after updating models
flask db upgrade
psql -U ${db_user} -d ${db_name} -a -f sql/seed-data.sql
echo "To run type: ./run.sh"
echo "============================="
echo "Access in web browser: via http://localhost:4000/"
