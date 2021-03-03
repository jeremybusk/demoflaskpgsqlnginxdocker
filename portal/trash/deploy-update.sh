#!/bin/bash
set -ex
shopt -s expand_aliases

echo "Running demoportal file deploy/refresh."

eval "$(ssh-agent -s)"
chmod 600 ../../../cicd/id_ed25519
ssh-add ../../../cicd/id_ed25519

app_user="demoportal"
app_host="demoportal.uvoo.io"
ssh_port=22
if [[ ! $(host demoportal.uvoo.io) == *"10.64"* ]]; then
    # Firewall socket for DNAT
    ssh_port=40001
    app_host="prv1.uvoo.io"
fi
app_dir="/var/lib/${app_user}"
app_host_dir="${app_host}:${app_dir}"
ssh_opts="-o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectionAttempts=10"
ssh_cmd="ssh -l root -p ${ssh_port} ${ssh_opts}"
alias ssh="${ssh_cmd}"
alias scp="scp ${ssh_opts}"

rsync_exclude="--exclude={__pycache__,*.pyc,*.egg-info,venv}"
# rsync_exclude="--exclude={__pycache__,*.pyc}"
# rsync_perms="--chown=${app_user}:${app_user} --chmod=D0770,F440"
rsync_perms="--chown=${app_user}:${app_user}"
alias rsync="rsync -avz ${rsync_perms} ${rsync_exclude} --rsync-path=\"sudo rsync\" -e \"${ssh_cmd}\""
rsync ./* "${app_host_dir}"/
ssh "${app_host}" "set -x; sudo ${app_dir}/upgrade-db-pkgs.sh"
