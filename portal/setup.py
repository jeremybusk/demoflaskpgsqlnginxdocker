from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='portal',
    version="0.0.1",
    packages=['portal'],
    include_package_data=True,
    install_requires=[
        'bootstrap-flask',
        #'click',
        #'click-repl',
        'cryptography',
        'dominate',
        'flake8',
        'flask-cors',
        'flask-login',
        'flask-migrate',
        'flask-moment',
        'flask_nav',
        'flask_sessionstore',
        'flask-sqlalchemy',
        'flask-wtf',
        'flask',
        'gunicorn',
        'itsdangerous',
        'jinja2',
        'prompt_toolkit',
        'pyjwt',
        'pypng',
        'pyyaml',
        'markupsafe',
        'onetimepass',
        #'psycopg2',
        'psycopg2-binary',
        'pyqrcode',
        'redis',
        'requests',
        'six',
        'sqlalchemy',
        'systemd-python',  # requires pkg-config libsystemd-dev
        'visitor',
        #'werkzeug',
        'werkzeug<2',
        'wtforms[email]',
        #'werkzeug<1', # for contrib  from werkzeug.middleware.proxy_fix import ProxyFix
        'wheel',
        'wtforms'
    ],
    author="Jeremy Busk",
    author_email="jeremybusk@gmail.com",
    description="Example Portal",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jeremybusk/",
    # packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
