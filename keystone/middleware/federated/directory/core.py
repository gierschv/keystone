from keystone import catalog

import webob.dec
import webob.exc
import json

def getProviderList():
    list = []
    service_catalog = catalog.controllers.ServiceV3()
    services = service_catalog.list_services({"is_admin":"True", "query_string": {}, "path":""})
    for service in services["services"]:
        if "idp" in service["type"]:
            list.append(service)
    return valid_Response({'realms':list})

def valid_Response(response):
    resp = webob.Response(content_type='application/json')
    resp.body = json.dumps(response)
    return resp
