'''
Created on 4 Jun 2013

@author: kwss
'''
import webob.dec

from keystone.common import wsgi
from keystone.common import config
from keystone.common import logging

from keystone.openstack.common import jsonutils

from keystone import catalog


CONF = config.CONF
LOG = logging.getLogger(__name__)

class DiscoveryService(wsgi.Middleware):
    '''
    Middleware to distribute information about available Identity Sources
    for federated access.
    
    Queries the directory when an authentication assertion is received to
    retrieve the validation information for the given provider.
    
    '''
    def __init__(self, *args, **kwargs):
        self.discovery = DefaultDiscovery()
        return super(DiscoveryService, self).__init__(*args, **kwargs)
        
        
    def process_request(self, request):
        if not request.body:
            return
        req = jsonutils.loads(request.body)
        # If this is not an authentication request then abort
        auth = req.get("auth", None)
        if not auth:
            return
        identity = auth.get("identity", None)
        if not identity:
            return
        # If this is not federated auth then abort
        try:
            federated = identity["federated"]
        except KeyError:
            LOG.debug("No federated data found, aborting authentication")
            return
        # If a provider ID not available and there is no data for federated 
        # then return a list of providers
        provider = federated.get("provider_id", None)
        if not provider and len(federated) == 0:
            return jsonutils.dumps(self.discovery.get_directory())
        # There is no provider ID but data in the dict, continue
        elif not provider:
            return
        
        # Otherwise modify the dict with the validation data and continue
        self.discovery.populate_auth_dict(federated, provider)
        print auth
        request.body = jsonutils.dumps({"auth":auth})
        return
        
class DefaultDiscovery(object):
    
    
    def __init__(self):
        self.catalog_api = catalog.Manager()
    
    def get_directory(self):
        return self.format_directory(self.catalog_api.list_services({"is_admin":True}))
    
    def populate_auth_dict(self, federated, provider):
        endpoints = self.catalog_api.list_endpoints({"is_admin":True})
        service = self.catalog_api.get_service({"is_admin":True}, provider)
        for endpoint in endpoints:
            if not endpoint["interface"]=="public":
                endpoints.pop(endpoints.index(endpoint))
            elif endpoint["service_id"]==service["id"]:
                validation = endpoint.get("validation", None)
                if validation is None:
                    validation = "missing"
                federated["validation"] = validation
        federated["protocol"] = service["type"].split(".")[1]
    
    def format_directory(self, services):
        providers = []
        endpoints = self.catalog_api.list_endpoints({"is_admin":True})
        for service in services:
            if service["type"].startswith("idp"):
                for endpoint in endpoints:
                    if not endpoint["interface"]=="public":
                        endpoints.pop(endpoints.index(endpoint))
                    elif endpoint["service_id"]==service["id"]:
                        providers.append({"service":{"id": service["id"], "url": endpoint["url"], "name": service["name"]}})
        return {"providers": providers}    
        
        