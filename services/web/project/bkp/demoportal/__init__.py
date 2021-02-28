import demoportal.utils
from demoportal import tests
tests.pre_start_tests()

from flask import Flask
app = Flask(__name__)


import demoportal.initapp
import demoportal.cli
import demoportal.views
import demoportal.models
import demoportal.unittests
