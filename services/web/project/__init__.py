import demoportal.utils
from demoportal import tests
tests.pre_start_tests()

from flask import Flask
app = Flask(__name__)


import project.initapp
import project.cli
import project.views
import project.models
import project.unittests
# import demoportal.unittests
