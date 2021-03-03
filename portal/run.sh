#!/bin/bash
set -e

export FLASK_APP=demoportal
export FLASK_ENV=development
export SQLALCHEMY_TRACK_MODIFICATIONS=True
export FLASK_RUN_PORT=4000
flask run
