from flask.cli import FlaskGroup

# from project import models, tests, utils, views, app
from project import models, utils, views, app


cli = FlaskGroup(app)


# @cli.command("create_db")
# def create_db():
#     db.drop_all()
#     db.create_all()
#    db.session.commit()


# @cli.command("seed_db")
# def seed_db():
#    db.session.add(User(email="jeremybusk@gmail.com"))
#    db.session.add(User(email="jeremybusk@uvoo.io"))
#    db.session.commit()


if __name__ == "__main__":
    cli()


# import project.utils
# from project import tests
# tests.pre_start_tests()

# from flask import Flask
# app = Flask(__name__)


# import project.views
# import project.models


# import project.initapp
# import project.cli
# import project.unittests
# import demoportal.unittests
