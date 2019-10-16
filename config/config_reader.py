
import os
import json

# Read Config
def config_json_read():
    with open(os.path.join("config", "config.json"), "r") as config_file:
        data = json.load(config_file)
        return(data)