import os

import portal.utils
from portal import tests
tests.pre_start_tests()

from flask import Flask
# app = Flask(__name__)
# app = Flask(__name__, root_path='portal/')
# app = Flask(__name__, root_path='/app/portal')
app = Flask(__name__)
# app = Flask(__name__, root_path=os.path.join(os.getcwd(), 'portal'))
# app = Flask(__name__, root_path=os.path.join(os.getcwd(), 'portal'))


import portal.initapp
# import portal.cli
import portal.views
import portal.models
import portal.unittests
