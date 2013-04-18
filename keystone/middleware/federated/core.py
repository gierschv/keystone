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
from keystone import auth
from keystone import exception
from keystone.common import config
from keystone.mapping import controllers
from keystone.middleware.federated import directory, user_management
from keystone.openstack.common import jsonutils

import uuid
import imp
import os
import logging
import json
from keystone.common import wsgi
import webob.dec
import webob.exc

import json as simplejson

LOG = logging.getLogger(__name__)
CONF = config.CONF
class Request(webob.Request):
    pass


'''
Supposing the request respect the following specification:
    
    The HTTP heather has:

    X-Authentication-Type:federated
    
'''
        
TEMP_PASS = uuid.uuid4().hex
class FederatedAuthentication(wsgi.Middleware):
    
    def __init__(self, *args, **kwargs):
        '''
        Constructor
        '''
        super(FederatedAuthentication, self).__init__(*args, **kwargs)
        #self.conf = conf
        #self.app = app
        LOG.info('Starting federated middleware wrapper')
        LOG.info('Init FederatedAuthentication!')
        
        
        
    @webob.dec.wsgify(RequestClass=Request)
    def process_request(self,request):
        
        
        LOG.debug('Request intercepted by CVM')
        LOG.debug('--------------------------')

        if not 'HTTP_X_AUTHENTICATION_TYPE' in request.environ:
            return 
        if not request.environ['HTTP_X_AUTHENTICATION_TYPE'] in  ('federated'):
            return 
        body = request.body 
        data = jsonutils.loads(body)
       
        if 'idpResponse' in data:
            username, expires, validatedUserAttributes = self.validate(request, data, data['realm'])
            identity_api = identity.controllers.UserV3()
            user_manager = user_management.UserManager()
            user, tempPass = user_manager.manage(username, expires)
            resp = {}
            try:
                resp['unscopedToken'], resp['tenants'] = self.mapAttributes(data, validatedUserAttributes, user, tempPass)
            except exception.Unauthorized:
                user, tempPass = user_manager.manage(username, expires, updatePass=True)
                resp['unscopedToken'], resp['tenants'] = self.mapAttributes(data, validatedUserAttributes, user, tempPass)
            LOG.debug(resp)
            return valid_Response(resp)
        elif 'auth' in data:
            LOG.debug("We just want to check the token and domain and forward the request")
            self.setUserDomain(data)
            LOG.debug("We set the user data")
            request.body = jsonutils.dumps(data)
            return 
        elif 'idpNegotiation' in data:
			return self.negotiate(request, data, data['realm'])
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
        context['path'] = ""
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
        return ris.getIdPRequest(CONF.federated.requestSigningKey, CONF.federated.SPName, endpoint)

    def validate(self, req, data, realm):
        ''' Get the validated attributes '''
        catalog_api = catalog.controllers.ServiceV3()
        context = {'is_admin': True}
        service = catalog_api.get_service(context=context, service_id=realm['id'])['service']
        type = service["type"].split('.')[1]
        processing_module = load_protocol_module(type)
        cred_validator = processing_module.CredentialValidator()
        return cred_validator.validate(req, data['idpResponse'], service['id'])

    def negotiate(self, req, data, realm):
        ''' Process a negotiation between an Idp and client '''
        catalog_api = catalog.controllers.ServiceV3()
        context = {'is_admin': True}
        service = catalog_api.get_service(context=context, service_id=realm['id'])['service']
        type = service["type"].split('.')[1]
        processing_module = load_protocol_module(type)
        negotiation_processor = processing_module.Negotiator()
        return negotiation_processor.negotiate(req, data['idpNegotiation'])

    def mapAttributes(self, data, attributes, user, password):
        mapper = controllers.AttributeMappingController()
        identity_api = identity.controllers.UserV3()
        role_api = identity.controllers.RoleV3()
        project_api = identity.controllers.ProjectV3()
        domain_api = identity.controllers.DomainV3()
        context = {'is_admin': True}
        context_q = {'is_admin': True, "query_string":{}, "path":""}
        toMap = mapper.map(context, attributes=attributes)['attribute_mappings']
        user_id = user['id']
        old_roles = []
        old_projects = project_api.list_user_projects(context_q, user_id=user_id)
        LOG.debug("OLD USER PROJECTS")
        LOG.debug(old_projects)
        old_attributes = []
        for old in old_projects["projects"]:
            roles = role_api.list_grants(context_q, user_id=user_id, project_id=old["id"])
            for old_role in roles["roles"]:
                old_attributes.append({"project":old["id"], "role":old_role["id"], "domain": old["domain_id"]})
        all_domains = domain_api.list_domains(context_q)["domains"]
        for old in all_domains:
            roles = role_api.list_grants(context_q, user_id=user_id, domain_id=old["id"])
            for old_role in roles["roles"]:
                old_attributes.append({"domain":old["id"], "role":old_role["id"]})

        LOG.debug("OLD GRANTS")
        LOG.debug(old_attributes)
        if user.get('expires') is not None:
            user.pop("expires")
        avail_projects = []
        LOG.debug(toMap)
        for i in toMap:
            roles = []
            projects = []
            domains = []
            for it in i:
                for k, v in it.iteritems():
                    if v == 'role':
                        roles.append(k)
                    if v == 'project':
                        projects.append(k)
                    if v == 'domain':
                        domains.append(k)
            for d in domains:
                avail_projects.append({ "domain":d})
                for r in roles:
                    new_att = {"role":r, "domain": d}
                    if new_att in old_attributes:
                        index =old_attributes.index(new_att) 
                        old_attributes.pop(index)
                    role_api.create_grant(context, user_id=user_id, role_id=r, domain_id=d)
            for p in projects:
                avail_projects.append({"project":p})
                for r in roles:
                    LOG.debug("Adding role "+r+" to user "+user['name']+" on project "+p)
                    new_att = {"project":p, "role":r, "domain": project_api.get_project(context, project_id=p)["project"]["domain_id"]}
                    if new_att in old_attributes:
                        index =old_attributes.index(new_att)                
                        old_attributes.pop(index)
                    role_api.create_grant(context, user_id=user_id, project_id=p, role_id=r)
        context['query_string'] = {}
        context["method"] = "password"
        token_api = auth.controllers.Auth()
        LOG.debug(old_attributes)
        for old in old_attributes:
            if old.get("project", None) is not None:
                role_api.revoke_grant(context, user_id=user_id, project_id=old["project"], role_id=old["role"])
            else:
                role_api.revoke_grant(context, user_id=user_id, domain_id=old["domain"], role_id=old["role"])
        LOG.debug("getting unscoped token")
        unscoped_token = token_api.authenticate_for_token(context, auth={"identity": {"methods": ["password"],"password": {"user": {"id": user_id, "password": password}}}})
        projectsToReturn = []
        for proj in avail_projects:
            temp_proj = {}
	    if proj.get("project", None) is not None:
                temp_proj["project"] = project_api.get_project(context, project_id=proj["project"])["project"]
                if temp_proj["project"].get("domain_id", None) is not None:
                    temp_proj["project"]["domain"] = domain_api.get_domain(context, domain_id=temp_proj["project"]["domain_id"])["domain"]
            if proj.get("domain", None) is not None:
                temp_proj["domain"] = domain_api.get_domain(context, domain_id=proj["domain"])["domain"]
            projectsToReturn.append(temp_proj)
        token_data = jsonutils.loads(unscoped_token.body)
        header = unscoped_token.headers.get("X-Subject-Token")
        return header, projectsToReturn

    def setUserDomain(self, data):
        token_api = auth.controllers.Auth()
        if data["auth"].get("token", None) is not None:
            token_id = data["auth"]["token"]["id"]
        else:
            token_id = data["auth"]["identity"]["token"]["id"]
        token_data = token_api.validate_token({"is_admin": True, "query_string":{}, "subject_token_id": token_id})
        domain_id = None
        if 'tenantId' in data['auth']:
            # It's a tenant so find it's domain
            project_api = identity.controllers.ProjectV3()
            domain_id = project_api.get_project({"is_admin": True, "query_string":{}}, project_id=data["auth"]["tenantId"])["project"]["domain_id"]
        elif 'domainId' in data['auth']:
            domain_api = identity.controllers.DomainV3()
            domain_id = domain_api.get_domain({"is_admin": True, "query_string":{}}, domain_id=data["auth"]["domainId"])["domain"]["id"]
        if domain_id is None:
            # Nothing to do here
            return;
        token_data = jsonutils.loads(token_data.body)
        user_api = identity.controllers.UserV3()
        user_ref = user_api.get_user({"is_admin": True, "query_string":{}}, user_id=token_data["token"]["user"]["id"]) 
        user_ref["user"]["domain_id"] = domain_id 
        user_api.update_user({"is_admin": True}, user=user_ref["user"], user_id=user_ref["user"]["id"])


protocol_modules = {}
def load_protocol_module(protocol):
    ''' Dynamically load correct module for processing authentication
        according to identity provider's protocol'''
    global protocol_modules
    if protocol not in protocol_modules:
        protocol_modules[protocol] = imp.load_source(protocol, os.path.dirname(__file__)+'/'+protocol+".py")
    return protocol_modules[protocol]
        

'''def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return FederatedAuthentication(app, conf)
    return auth_filter'''

def valid_Response(response):
    resp = webob.Response(content_type='application/json')
    resp.body = json.dumps(response)
    return resp
