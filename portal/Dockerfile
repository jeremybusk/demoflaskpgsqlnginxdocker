# pull official base image
# FROM python:3.8.1-slim-buster
FROM python:3.9.2-buster
# FROM python:slim-buster

# set work directory
WORKDIR /app
# WORKDIR /

# set environment variables
# ENV PYTHONDONTWRITEBYTECODE 1
# ENV PYTHONUNBUFFERED 1

# install system dependencies
# RUN apt-get update && apt-get install -y netcat
# RUN apt-get install -y libpq-dev python-dev pkg-config
# RUN apt-get install -y libpq-dev python-dev pkg-config
# RUN apt-get install -y curl jq pkg-config libsystemd-dev libsystemd-dev libpq-dev python3-dev gcc postgresql python3-pip
# RUN apt-get install -y curl jq pkg-config libsystemd-dev libsystemd-dev libpq-dev python3-dev gcc postgresql python3-pip
RUN apt-get update && apt-get install -y curl jq pkg-config libsystemd-dev libsystemd-dev libpq-dev python3-dev gcc postgresql netcat
# pkg-config libsystemd-dev libsystemd-dev libpq-dev python3-dev postgresql curl jq

# install dependencies
# RUN pip install --upgrade pip
# RUN pip install --upgrade pip
# --no-cache-dir --prefer-binary
# RUN pip3 install --upgrade pip3
# COPY ./requirements.txt /app/requirements.txt
# RUN pip install -r requirements.txt

# python setup.py develop

# copy project
COPY . /app/
# COPY . /
# RUN pipenv --rm
RUN python3 setup.py install
# RUN pip install -r requirements.txt

# run entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
# ENTRYPOINT ["/entrypoint.sh"]
