#!/bin/bash
set -e

sudo apt-get install -y postgresql

db_name="demoportal"
db_user="demoportal"
db_pass="pleasechangeme"

if [[ $1 == 'drop' ]]; then
    echo "Dropping database."
    sudo -u postgres dropdb $db_name 
    sudo -u postgres dropuser $db_user 
fi

query="SELECT 1 FROM pg_roles WHERE rolname='${db_user}'"
if [[ $(sudo -u postgres psql -tAc "${query}" | grep "^1$") ]]; then
    echo "DB role ${db_user} already exists."
else
    sudo -u postgres psql -c \
        "CREATE ROLE ${db_user} WITH SUPERUSER LOGIN PASSWORD '${db_pass}'"
fi

if [[ $(sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -w ${db_name}) ]]; then
    echo "Database ${db_name} already exists."
else
    sudo -u postgres createdb -O ${db_user} -E Unicode -T template0 ${db_name}
fi
