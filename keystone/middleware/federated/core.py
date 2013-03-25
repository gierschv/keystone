'''
 * Copyright (c) 2011, University of Kent
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution. 
 *
 * 1. Neither the name of the University of Kent nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission. 
 *
 * 2. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS  
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 * PURPOSE ARE DISCLAIMED. 
 *
 * 3. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 4. YOU AGREE THAT THE EXCLUSIONS IN PARAGRAPHS 2 AND 3 ABOVE ARE REASONABLE
 * IN THE CIRCUMSTANCES.  IN PARTICULAR, YOU ACKNOWLEDGE (1) THAT THIS
 * SOFTWARE HAS BEEN MADE AVAILABLE TO YOU FREE OF CHARGE, (2) THAT THIS
 * SOFTWARE IS NOT "PRODUCT" QUALITY, BUT HAS BEEN PRODUCED BY A RESEARCH
 * GROUP WHO DESIRE TO MAKE THIS SOFTWARE FREELY AVAILABLE TO PEOPLE WHO WISH
 * TO USE IT, AND (3) THAT BECAUSE THIS SOFTWARE IS NOT OF "PRODUCT" QUALITY
 * IT IS INEVITABLE THAT THERE WILL BE BUGS AND ERRORS, AND POSSIBLY MORE
 * SERIOUS FAULTS, IN THIS SOFTWARE.
 *
 * 5. This license is governed, except to the extent that local laws
 * necessarily apply, by the laws of England and Wales.
'''


'''
Created on 30 Jan 2013

@author: Kristy Siu
'''
from keystone import catalog
from keystone import identity
from keystone import token
from keystone.mapping import controllers
from keystone.middleware.federated import directory, user_management

import uuid
import imp
import os
import logging
import json

import webob.dec
import webob.exc

import json as simplejson

LOG = logging.getLogger(__name__)

class Request(webob.Request):
    pass


'''
Supposing the request respect the following specification:
    
    The HTTP heather has:

    X-Authentication-Type:federated
    
'''
        

class FederatedAuthentication(object):
    
    def __init__(self, app, conf):
        '''
        Constructor
        '''
        self.conf = conf
        self.app = app
                
        LOG.info('Starting federated middleware wrapper')
        LOG.info('Init FederatedAuthentication!')
        
        
        
    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self,req):
        
        
        LOG.debug('Request intercepted by CVM')
        LOG.debug('--------------------------')
        if not 'HTTP_X_AUTHENTICATION_TYPE' in req.environ:
            return self.app(req)
        if not req.environ['HTTP_X_AUTHENTICATION_TYPE'] in  ('federated'):
            return self.app(req)
        
        body = req.body 
        data = simplejson.loads(body)
        print data

        if 'idpResponse' in data:
            username, expires, validatedUserAttributes = self.validate(req, data, data['realm'])
            if type(username) == dict:
                resp = username
            else:
                identity_api = identity.controllers.UserV3()
                user_manager = user_management.UserManager()
                user, tempPass = user_manager.manage(username, expires)
                resp = {}
                resp['unscopedToken'], resp['tenants'] = self.mapAttributes(data, validatedUserAttributes, user, tempPass)
            return valid_Response(resp)
        elif 'idpNegotiation' in data:
			return self.negotiate(data)
        else:
            if 'realm' in data:
                realm_id = data['realm']
                return self.getRequest(realm_id)
            
            return directory.getProviderList()

    def getRequest(self, realm):
        ''' Get an authentication request to return to the client '''
        catalog_api = catalog.controllers.ServiceV3()
        endpoint_api = catalog.controllers.EndpointV3()
        context = {'is_admin': True}
        service = catalog_api.get_service(context=context, service_id=realm['id'])['service']
        protocol = service['type'].split('.')[1]
        processing_module = load_protocol_module(protocol)
        context['query_string'] = {}
        context['query_string']['service_id'] = service['id']
        endpoints = endpoint_api.list_endpoints(context)['endpoints']
        endpoint = None
        if not len(endpoints) < 1:
            for e in endpoints:
                if e['interface'] == 'public':
                    endpoint = e['url']
        else:
            LOG.error('No endpoint found for this service')
        ris = processing_module.RequestIssuingService()
        return ris.getIdPRequest(self.conf['requestSigningKey'], self.conf['SPName'], endpoint)

    def validate(self, req, data, realm):
        ''' Get the validated attributes '''
        catalog_api = catalog.controllers.ServiceV3()
        context = {'is_admin': True}
        service = catalog_api.get_service(context=context, service_id=realm['id'])['service']
        type = service["type"].split('.')[1]
        processing_module = load_protocol_module(type)
        cred_validator = processing_module.CredentialValidator()
        return cred_validator.validate(req, data['idpResponse'], service['id'])

    def negotiate(self, data):
        ''' Process a negotiation between an Idp and client '''
        catalog_api = catalog.controllers.ServiceV3()
        context = {'is_admin': True}
        service = catalog_api.get_service(context=context, service_id=realm['id'])['service']
        type = service["type"].split('.')[1]
        processing_module = load_protocol_module(type)
        negotiation_processor = processing_module.Negotiator()
        return negotiation_processor(data['idpNegotiation'])

    def mapAttributes(self, data, attributes, user, password):
        print "mapAttributes: %r %r %r %r" % (data, attributes, user, password)

        mapper = controllers.AttributeMappingController()
        identity_api = identity.controllers.UserV3()
        legacy_identity_api = identity.controllers.User()
        role_api = identity.controllers.RoleV3()
        project_api = identity.controllers.ProjectV3()
        context = {'is_admin': True}
        print 'BEFORE MAPPING: %r' % attributes
        toMap = mapper.map(context, attributes=attributes)['attribute_mappings']
        print 'MAPPED: %r' % toMap

        user_id = user['id']
        if user.get('expires') is not None:
            user.pop("expires")
        roles = []
        projects = []
        domains = []
        for k, v in toMap.iteritems():
            if v == 'role':
                roles.append(k)
            if v == 'project':
                projects.append(k)
            if v == 'domain':
                domains.append(k)
        for d in domains:
            for p in projects:
                for r in roles:
                    identity_api.add_role_to_user(context, user_id=user_id, project_id=p, role_id=r)
        if len(domains) == 0:
            for p in projects:
                user["tenantId"] = p
                legacy_identity_api.update_user_tenant(context, user['id'], user)
                for r in roles:
                    LOG.debug("Adding role "+r+" to user "+user['name']+" on project "+p)
                    role_api.create_grant(context, user_id=user_id, project_id=p, role_id=r)
        LOG.debug(user)
        context['query_string'] = {}
        token_api = token.controllers.Auth()
        unscoped_token = token_api.authenticate(context, auth={'passwordCredentials': {'username': user['name'], 'password': password}})
        return unscoped_token['access']['token']['id'], [project_api.get_project(context, project_id=p)['project']  for p in projects]

protocol_modules = {}
def load_protocol_module(protocol):
    ''' Dynamically load correct module for processing authentication
        according to identity provider's protocol'''
    global protocol_modules
    if protocol not in protocol_modules:
        protocol_modules[protocol] = imp.load_source(protocol, os.path.dirname(__file__)+'/'+protocol+".py")
    return protocol_modules[protocol]
        

def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return FederatedAuthentication(app, conf)
    return auth_filter

def valid_Response(response):
    resp = webob.Response(content_type='application/json')
    resp.body = json.dumps(response)
    return resp
