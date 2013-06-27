'''
Created on 7 Jun 2013

@author: kwss
'''

from keystone import auth
from keystone import exception
from keystone.common import config
from keystone.common import logging
from keystone.openstack.common import importutils

from keystone.auth.plugins.federated import user_management

METHOD_NAME = "federated"

CONF = config.CONF
LOG = logging.getLogger(__name__)

PROTOCOLS = {}

def load_auth_protocol(protocol_name):
    if protocol_name not in CONF.auth.protocols:
        raise exception.AuthProtocolNotSupported()
    driver = CONF.auth.get(protocol_name)
    return importutils.import_object(driver)


def get_auth_protocol(protocol_name):
    global PROTOCOLS
    if protocol_name not in PROTOCOLS:
        PROTOCOLS[protocol_name] = load_auth_protocol(protocol_name)
    return PROTOCOLS[protocol_name]


class Federated(auth.AuthMethodHandler):
    
    def __init__(self):
        self.discovery_driver = importutils.import_object(CONF.auth.get("discovery"))
        self.mapping_api = importutils.import_object(CONF.auth.get("attribute_mapper"))
        self.issuing_policy = importutils.import_object(CONF.auth.get("issuing_policy"))

    def authenticate(self, context, auth_payload, auth_context):
        ''' Authenticate the user, auth_payload should contain:
            protocol - the protocol the identity provider uses
            provider_id - an identifier for the identity provider
            negotiation (Optional) - an intermediate communication
            assertion - an authentication assertion to be validated '''
        # Grab the phase parameter
        phase = auth_payload.get("phase", None)
        
        if not phase:
            return "Federated Requests must specify which stage of authentication has been reached"
        try:
            response = getattr(self, phase)(auth_payload)
        except AttributeError as e:
            return "Authentication phase not supported: " + e.message
        
        if response.get("response") is not None:
            return response.get("response")
        
        else:
            auth_context["user_id"] = user_management.UserManager().manage(response["uid"])
        
        return    
    
    def discovery(self, auth_payload):
        ''' Return a list of available Identity Providers'''
        return {"response": self.discovery_driver.get_directory()}
    
    def request(self, auth_payload):
        ''' 
        Create an authentication request for the provider in the auth payload.
        If a provider is not specified the return error message '''
        
        if not auth_payload.get("provider_id"):
            return {"response":"Identity Provider not found or not recognised"}
        print auth_payload
        self.discovery_driver.populate_auth_dict(auth_payload,
                                                 auth_payload.get("provider_id"))
        
        print auth_payload
        
        protocol = auth_payload["protocol"]
        response = get_auth_protocol(protocol).request_auth(auth_payload)
        return {"response": response}
    
    def negotiate(self, auth_payload):
        if not auth_payload.get("provider_id"):
            return {"response":"Identity Provider not found or not recognised"}
        if not auth_payload.get("protocol"):
            auth_payload["protocol"] = "saml"
        response = get_auth_protocol(auth_payload["protocol"]).negotiate(auth_payload)
        return {"response" : response}
    
    def validate(self, auth_payload):
        if not auth_payload.get("provider_id"):
            return {"response":"Identity Provider not found or not recognised"}
        if not auth_payload.get("protocol"):
            auth_payload["protocol"] = "saml"
        response = {"response": None}
        response["uid"], response["attributes"], response["expiry"] = get_auth_protocol(auth_payload["protocol"]).validate(auth_payload)
        return response
        
        