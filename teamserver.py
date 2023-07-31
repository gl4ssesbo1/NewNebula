import json
import sys, os
from termcolor import colored
from flask import Flask
from waitress import serve
from database.db import initialize_db
from pymongo import ReadPreference
import multiprocessing

from core.models.Listeners import listener_blueprint
from core.models.Cosmonaut import cosmonaut_blueprint
from core.models.Modules import module_blueprint
from core.models.AWSCredentials import awscredentials_blueprint
from core.models.AWSIAM import awsusers_blueprint
from core.models.AZURECredentials import azurecredentials_blueprint
from core.models.DigitalOceanCredentials import digitaloceancredentials_blueprint
from core.models.Domains import domains_blueprint
from core.models.ClientCommands import clientcommands_blueprint

from getpass import getpass

import argparse
import docker
import socket
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from database.models import Cosmonaut
import string, random
import mongoengine
from flask_bcrypt import generate_password_hash

from Listeners.WebSocket.server import WebsocketServer
from Listeners.WebSocket.server import start_websocket_listener

from database.models import WebsocketListener

parser = argparse.ArgumentParser(description='------ Nebula Teamserver Options ------')
parser.add_argument('-ah', '--apiHost', type=str, help='The API Server Host. (Default: 127.0.0.1)', default='127.0.0.1')
parser.add_argument('-ap', '--apiPort', type=int, help='The API Server Port. (Default: 5000)', default=5000)
parser.add_argument('-dh', '--databaseHost', type=str, help='The MongoDB Database Server Host. (Default: localhost)', default='localhost')
parser.add_argument('-dp', '--databasePort', type=int, help='The MongoDB Database Server Port. (Default: 27017)', default=27017)
parser.add_argument('-dn', '--databaseName', type=str, help='The MongoDB Database Name. (Required)', required=True)
parser.add_argument('-p', '--password', type=str, help='The password for user \'cosmonaut\'. (Required)')
args = parser.parse_args()

if args.password:
    password = args.password
else:
    password = getpass("Password: ")
    while password == "":
        password = getpass("Password: ")

all_count = 0
show = [
    'cleanup',
    'detection',
    'detectionbypass',
    'enum',
    'exploit',
    'lateralmovement',
    'listeners',
    'persistence',
    'privesc',
    'reconnaissance',
    'stager',
    'misc',
    'postexploitation'
]

nr_of_modules = {
    'cleanup':"",
    'detection':"",
    'detectionbypass':"",
    'enum':"",
    'exploit':"",
    'lateralmovement':"",
    'listeners':"",
    'persistence':"",
    'privesc':"",
    'reconnaissance':"",
    'stager':"",
    'misc':"",
    'postexploitation': ""
}
for module in show:
    module_count = 0
    arr = os.listdir("./module/" + module)
    for x in arr:
        if "__" in x:
            continue
        elif ".git" in x:
            continue
        else:
            module_count += 1
            all_count += 1
    if module_count == 0:
        nr_of_modules[module] = "0"
    else:
        nr_of_modules[module] = module_count

nr_of_cloud_modules = {
    "aws":0,
    "gcp":0,
    "azure":0,
    "o365":0,
    "docker":0,
    "kube":0,
    "misc":0,
    "azuread": 0,
    "digitalocean": 0
}
clouds = [
    "aws",
    "gcp",
    "azure",
    "o365",
    "docker",
    "kube",
    "azuread",
    "misc",
    "digitalocean"
]
for cloud in clouds:
    module_count = 0
    for module in show:
        arr = os.listdir("./module/" + module)
        for x in arr:
            if "__" in x:
                continue
            elif ".git" in x:
                continue
            else:
                if x.split("_")[0] == cloud:
                    module_count += 1
    nr_of_cloud_modules[cloud] = module_count

input_text = colored('------------------------------------------------------------\n', "green")
input_text += colored('''           _   _      _           _                      
          | \ | |    | |         | |                     
          |  \| | ___| |__  _   _| | __ _                
          | . ` |/ _ \ '_ \| | | | |/ _` |               
  _______ | |\  |  __/ |_) | |_| | | (_| |               
 |__   __||_| \_|\___|_.__/ \__,_|_|\__,_|               
    | | ___  __ _ _ __ ___  ___  ___ _ ____   _____ _ __ 
    | |/ _ \/ _` | '_ ` _ \/ __|/ _ \ '__\ \ / / _ \ '__|
    | |  __/ (_| | | | | | \__ \  __/ |   \ V /  __/ |   
    |_|\___|\__,_|_| |_| |_|___/\___|_|    \_/ \___|_|   
''', 'blue')
input_text += (colored('-------------------------------------------------------------\n', "green"))
input_text += ("{} aws\t\t{} gcp\t\t{} azure\t\t{} office365\n".format(nr_of_cloud_modules['aws'], nr_of_cloud_modules['gcp'],
                                                            nr_of_cloud_modules['azure'], nr_of_cloud_modules['o365']))
input_text += (
    "{} docker\t{} kubernetes\t{} misc\t\t{} azuread\n".format(nr_of_cloud_modules['docker'], nr_of_cloud_modules['kube'],
                                                             nr_of_cloud_modules['misc'],
                                                             nr_of_cloud_modules['azuread']))
input_text += (
    "{} digitalocean\n".format(nr_of_cloud_modules['digitalocean']))

input_text += (colored("-------------------------------------------------------------\n", "green"))
input_text += ("{} modules\t{} cleanup\t\t{} detection\n".format(all_count, nr_of_modules['cleanup'], nr_of_modules['detection']))
input_text += ("{} enum\t\t{} exploit\t\t{} persistence\n".format(nr_of_modules['enum'], nr_of_modules['exploit'],
                                                       nr_of_modules['persistence']))
input_text += ("{} listeners\t{} lateral movement\t{} detection bypass\n".format(nr_of_modules['listeners'],
                                                                      nr_of_modules['lateralmovement'],
                                                                      nr_of_modules['detectionbypass']))
input_text += ("{} privesc\t{} reconnaissance\t{} stager\t{}postexploitation\n".format(nr_of_modules['privesc'], nr_of_modules['reconnaissance'],
                                                        nr_of_modules['stager'], nr_of_modules['postexploitation']))
input_text += ("{} misc\n".format(nr_of_modules['misc']))

print(input_text)
app = Flask(__name__)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

jwt_token = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(32))
app.config['JWT_SECRET_KEY'] = jwt_token

host = args.databaseHost
port = args.databasePort

database = args.databaseName

'''
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://{}:{}/{}'.format(host, port, workspace),
}
'''
try:
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    location = ("127.0.0.1", port)
    result_of_check = a_socket.connect_ex(location)

    if result_of_check == 0:
        mongo_instance_verify = input(colored("[*] Port is busy. Is a MongoDB instance running there? [y/N] ", "red"))
        if not mongo_instance_verify.strip().replace("\n", "") == 'y' and not mongo_instance_verify.strip().replace(
                "\n", "") == 'Y':
            print(colored("[*] Choose another port or stop the other service!", "red"))
            exit()
    else:
        print(colored("[*] Pulling MongoDB Image...", "green"))
        client = docker.from_env()
        client.images.pull('mongo')
        print(colored("[*] MongoDB Image Pulled!", "green"))

        workspace_directory = "/home/testdocker/datafolder"

        if not os.path.exists("{}/workspaces/".format(os.getcwd())):
            os.mkdir("{}/workspaces/".format(os.getcwd()))

        if not os. path.exists("./workspaces/{}".format(database)):
            os.mkdir("{}/workspaces/{}".format(os.getcwd(), database))

        container = client.containers.run(
            'mongo',
            ports={
                #port:('127.0.0.1',port)
                port:('0.0.0.0',port)
            },
            volumes={
                workspace_directory: {
                    'bind': "/data/db",
                    'mode': 'rw'
                }
            },
            detach=True
        )

        print("{} '{}'".format(
            colored("[*] MongoDB started on container ID", "green"),
            colored(container.id, "blue")
        ))

    """app.config['MONGODB_SETTINGS'] = {
        'host': 'mongodb://{0}:{1}/{2}'.format(host, port, database)
        #'host': 'mongodb://{0}:{1},{0}:{2},{0}:{3}/{4}?replicaSet=mongodb-replicaset'.format(host, port, port+1, port+2, database)
    }"""

    app.config['MONGODB_DB'] = database
    app.config['MONGODB_HOST'] = host
    app.config['MONGODB_PORT'] = port
    app.config['MONGODB_CONNECT'] = False


    print(colored('------------------------------------------------------------', "green"))

    print("{} '{}'".format(
        colored("[*] JWT Secret Key set to:", "green"),
        colored(jwt_token, "blue")
    ))

    print("{} '{}:{}'".format(
        colored("[*] Database Server set to:", "green"),
        colored(host, "blue"),
        colored(port, "blue")
    ))

    print("{} '{}'".format(
        colored("[*] Database set to:", "green"),
        colored(database, "blue")
    ))

    # I am not using these on Nebula. So it's not an information disclosure. It's just sth I plan to use latter.
    '''
    app.config['MONGODB_USERNAME'] = 'user'
    app.config['MONGODB_PASSWORD'] = 'pass'
    '''
    initialize_db(app)

    try:
        body = {
            "cosmonaut_name": "cosmonaut",
            "cosmonaut_pass": password
        }
        cosmonaut = Cosmonaut(**body)
        cosmonaut.hash_password()
        cosmonaut.save()
    except mongoengine.errors.NotUniqueError as ex:
        cosmonaut = Cosmonaut.objects.get(cosmonaut_name=body['cosmonaut_name'])

        body['cosmonaut_pass'] = generate_password_hash(password).decode('utf8')
        cosmonaut.update(**body)


    print('{}{}{}'.format(
        colored("[*] User '", "green"),
        colored("cosmonaut", "blue"),
        colored("' was created!", "green")
        )
    )

    app.register_blueprint(listener_blueprint)
    app.register_blueprint(cosmonaut_blueprint)
    app.register_blueprint(module_blueprint)
    app.register_blueprint(awscredentials_blueprint)
    app.register_blueprint(awsusers_blueprint)
    app.register_blueprint(azurecredentials_blueprint)
    app.register_blueprint(digitaloceancredentials_blueprint)
    app.register_blueprint(domains_blueprint)
    app.register_blueprint(clientcommands_blueprint)

except SystemExit:
    exit()

except docker.errors.DockerException as ex:
    print(colored("[*] Please start the docker service. (service docker start)", "red"))
    exit()

except:
    e = sys.exc_info()
    if e == None or e == "":
        exit()
    else:
        print(colored("[*] {}".format(e), "red"))
        exit()

def startWebsocketListeners():
    try:
        websocket_listeners = json.loads(WebsocketListener.objects().to_json())

        if len(websocket_listeners) > 0:
            for wslistener in websocket_listeners:
                if wslistener['listener_status'] == "running":
                    wsbody = {
                        "listener_name": wslistener['listener_name'],
                        "listener_host": wslistener['listener_host'],
                        "listener_port": wslistener['listener_port'],
                        "listener_protocol": "WebSocket"
                    }

                    try:
                        p = multiprocessing.Process(target=start_websocket_listener,
                                                    args=(wslistener['listener_port'], None, None,))
                        p.start()

                        print(colored("[*] Listener '{}' started on host '{}' and port '{}'".format(
                            wslistener['listener_name'],
                            wslistener['listener_host'],
                            str(wslistener['listener_port'])
                        ), "green"))

                    except:
                        wslistener['listener_status'] = "dead"
                        try:
                            WebsocketListener.objects.get_or_404(listener_name=wslistener['listener_name']).update(
                                **wsbody)

                        except mongoengine.DoesNotExist:
                            WebsocketListener.save(**wsbody)

                        except:
                            print(colored("[*] Listener '{}' on host '{}' and port '{}' did not start".format(
                                wslistener['listener_name'],
                                wslistener['listener_host'],
                                str(wslistener['listener_port'])
                            ), "red"))
    except:
        e = sys.exc_info()
        if e == None or e == "":
            exit()
        else:
            print(colored("[*] {}".format(e), "red"))
            exit()

if __name__ == "__main__":
    apihost = args.apiHost
    apiport = args.apiPort
    print("{} '{}:{}'".format(
        colored("[*] API Server set to:", "green"),
        colored(apihost, "blue"),
        colored(apiport, "blue")
    ))
    print(colored('------------------------------------------------------------', "green"))

    startWebsocketListeners()

    serve(app, host=apihost, port=apiport)
