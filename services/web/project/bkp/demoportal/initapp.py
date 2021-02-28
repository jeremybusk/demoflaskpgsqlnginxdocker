import yaml
from flask_cors import CORS
from os.path import isfile
from demoportal import app
import sys
from werkzeug.contrib.fixers import ProxyFix

# home_dir = str(Path.home())
# demoportal_config_file = f'{home_dir}/.democli.yaml'
demoportal_config_file = f'config.yaml'
if not isfile(demoportal_config_file):
    sys.exit(f'E: Portal config file {demoportal_config_file} does not exist.')
with open(demoportal_config_file, 'r') as stream:
    try:
        config = yaml.safe_load(stream)
    except Exception as e:
        raise SystemExit(f"E: config issue {demoportal_config_file} of {e}")

app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = 'dev'
app.config.from_object('config.ProductionConfig')

# leaving for ref for immediate future
# app.config.from_object('yourapplication.default_settings')
# app.config.from_envvar('YOURAPPLICATION_SETTINGS')

CORS(app)
