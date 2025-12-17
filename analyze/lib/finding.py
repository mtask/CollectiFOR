import json

def new_finding():
    FINDING = json.dumps({
           "type": "",
           "message": "",
           "rule": "",
           "source_file": "",
           "tags": "",
           "meta": {},
           "namespace": "",
           "artifact": "",
           "indicator": ""
         })
    return json.loads(FINDING)
