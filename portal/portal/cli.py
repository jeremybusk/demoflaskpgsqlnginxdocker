import click
from flask_sqlalchemy import SQLAlchemy
from portal import app


@app.cli.command()
@click.argument('name')
def example(name):
    print(name)


@app.cli.command()
def initdata():
    with open('data/demoapp1-uuids.txt', 'r') as f:
        uuids = f.read().splitlines()

    db = SQLAlchemy(app)
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_TYPE'] = 'sqlalchemy'

    sql = "INSERT INTO products (name) VALUES ('demoapp1')"
    print(sql)
    db.engine.execute(sql)

    for uuid in uuids:
        sql = f"INSERT INTO licenses (product_id, uuid) VALUES (1, '{uuid}')"
        print(sql)
        db.engine.execute(sql)
