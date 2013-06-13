'''
Created on 7 Jun 2013

@author: kwss
'''
import imp
import os

from keystone import auth
from keystone import exception
from keystone.common import config
from keystone.common import logging
from keystone.openstack.common import importutils

from keystone.auth.plugins.federated import user_management


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
        self.mapping_api = importutils.import_object(CONF.auth.get("attribute_mapper"))
        self.issuing_policy = importutils.import_object(CONF.auth.get("issuing_policy"))
    
    


    

    def authenticate(self, context, auth_payload, auth_context):
        ''' Authenticate the user, auth_payload should contain:
            protocol - the protocol the identity provider uses
            provider_id - an identifier for the identity provider
            negotiation (Optional) - an intermediate communication
            assertion - an authentication assertion to be validated '''
        # Validate the request
        try:
            provider = auth_payload["provider_id"]            
        except KeyError as e:
            raise exception.ValidationError(attribute="provider_id", target=auth_payload)
        
        try:
            protocol = auth_payload["protocol"]      
        except KeyError as e:
            raise exception.ValidationError(attribute="protocol", target=auth_payload)
        

        validate_api = get_auth_protocol(protocol)
       
        # Negotiation / Request Issuing
        try:
            return validate_api.negotiate(auth_payload)
        except KeyError:
            pass
        # Validation
        assertion = auth_payload.get("assertion", None)
        if not assertion:
            raise exception.ValidationError(attribute="assertion", target=auth_payload)
        
        uid, attributes, validity = validate_api.validate(auth_payload)
        # Check Issuing Policy
        self.issuing_policy.check_issuers(attributes, provider)
        
        user_manager = user_management.UserManager()
        
        auth_context["user_id"] = user_manager.manage(uid)
        auth_context["validity"] = validity
        auth_context["attributes"] = self.mapping_api.map(attributes)
        return 
