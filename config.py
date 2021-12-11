import json


def load_config():
    patterns = dict()
    with open('patterns.json') as file:
        patterns = json.load(file)
    return patterns
