import os
import json

from flask import Flask
from flask_bootstrap import Bootstrap

app = Flask(__name__)
app.config.from_object('oidcrp.config')
app.secret_key = app.config['SECRET_KEY']
bootstrap = Bootstrap(app)

from oidcrp.client import Client

client_config = {}
with open('./client.json', 'r') as f:
    client_config = json.loads(f.read())

client = Client(client_config)    


from oidcrp import webserver
