# Install

Prepare environment.
```
source ./prep-env.sh
```

Setting flask environment variables.
```
export FLASK_APP=demoportal
export FLASK_ENV=development
export SQLALCHEMY_TRACK_MODIFICATIONS=True
export FLASK_RUN_PORT=4000
```

If you haven't already, initialize database. See Migrations.

Run Flask example.
```
flask run --host=0.0.0.0 --port=4000
```

# Database

## Add Role and Database

Create role and db with role as owner
```
create-db.sh
```

Drop database then create role and db with role as owner
```
create-db.sh drop
```

## Migrations

Migrations are handled by alembic

If new database initialize migrations
```
flask db init
```

After add/update to models.
```
flask db migrate
flask db upgrade 
```

# Running in Production

## Use gunicorn

* http://docs.gunicorn.org/en/stable/deploy.html
* https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-18-04

```
gunicorn -w 4 -b 127.0.0.1:4000 demoportal:app
```

As an alternative, you could use uwsgi or python waitress.

##

You could also add to __init__.py
```
if __name__ == '__main__':
   app.run(port=5001, host='0.0.0.0')
```
and start python3 demoportal/__init__.py
but should use the the flask run for development and gunicorn for production.

## Configure NGINX

#  References

* http://flask.pocoo.org/docs/1.0/cli/
* http://flask.pocoo.org/docs/dev/deploying/wsgi-standalone/

# Updating changes 

* Make code changes
* If making changes in models run `flask db migrate` and then git add migrations folder.
* CI script then will use deploy-update.sh to actually update live server.
