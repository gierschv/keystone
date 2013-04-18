'''
 * Copyright (c) 2013, University of Kent
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
Created on 8 March 2013

@author: Vincent Giersch
'''

import logging
from datetime import date, datetime, timedelta

import webob.dec
import webob.exc
import json
import platform
import moonshot

from keystone import identity
from keystone import mapping
from keystone import exception

LOG = logging.getLogger(__name__)


class RequestIssuingService(object):
    def __init__(self):
        pass

    def __call__(self):
        return None

    def getIdPRequest(self, key, issuer, endpoint):
        LOG.info('IssueRequest')
        resp = {
            'idpRequest': None,
            'idpEndpoint': {
                'mechanism': '{1 3 6 1 5 5 15 1 1 18}',
                'serviceName': 'keystone@%s' % platform.node()
            }
        }
        return build_response(resp)


class GssAPIContext(object):
    contexts = {}
    def __exit__(self, type, value, traceback):
        for cid in GssAPIContext.contexts.keys():
            LOG.debug('Clean GSSAPI context: %s', cid)
            self.destroyClientContext(cid)

    def setClientContext(self, cid, context):
        # TODO: add to conf file
        context['expires'] = datetime.now() + timedelta(seconds=60)
        GssAPIContext.contexts[cid] = context

    def getClientContext(self, cid):
        self.cleanExpiredContextes()
        if cid in GssAPIContext.contexts:
            return GssAPIContext.contexts[cid]
        return None

    def cleanExpiredContextes(self):
        for cid in GssAPIContext.contexts.keys():
            if GssAPIContext.contexts[cid]['expires'] < datetime.now():
                LOG.debug('Clean expired GSSAPI context: %s', cid)
                self.destroyClientContext(cid)

    def destroyClientContext(self, cid=None, context=None, clean=True):
        try:
            if cid is not None:
                if cid in GssAPIContext.contexts:
                    moonshot.authGSSServerClean(GssAPIContext.contexts.pop(cid)['context'])
            if context is not None:
                moonshot.authGSSServerClean(context)
        except Exception, err:
            LOG.error('GSS clean error: %s' % err)

    def clientId(self, req):
        return req.remote_addr + '.' + req.environ['REMOTE_PORT']


class MoonshotException(Exception):
    pass


# TODO: timeout ctx
class Negotiator(GssAPIContext):
    def __init__(self):
        pass

    def negotiate(self, req, data):
        cid = self.clientId(req)
        context = self.getClientContext(cid)
        resp = {'idpNegotiation': None}

        try:
            # Init
            if context is None:
                context = {}
                result, context['context'] = moonshot.authGSSServerInit('keystone@%s' % platform.node(), '{1 3 6 1 5 5 15 1 1 18}')
                if result != 1:
                    raise MoonshotException('moonshot.authGSSServerInit returned result %d' % result)

            # Negotiate steps
            context['state'] = moonshot.authGSSServerStep(context['context'], data)
            self.setClientContext(cid, context)
            resp = {'idpNegotiation': moonshot.authGSSServerResponse(context['context'])}
        except (moonshot.KrbError, MoonshotException), err:
            LOG.error(err)
            self.destroyClientContext(cid, context['context'])
            raise exception.CredentialNotFound()
        return build_response(resp)


class CredentialValidator(GssAPIContext):
    def __init__(self):
        self.org_mapping_api = mapping.controllers.OrgMappingController()
        self.mapping_api = mapping.controllers.AttributeMappingController()
        pass
    
    def __call__(self):
        return None
        
    def validate(self, req, response, realm_id):
        LOG.debug("CredentialValidator/validate")
        cid = self.clientId(req)
        context = self.getClientContext(cid)

        try:
            if type(context) == dict and context['state'] == moonshot.AUTH_GSS_COMPLETE:
                username = moonshot.authGSSServerUserName(context['context'])
                LOG.debug('USERNAME = %s', username)

                LOG.debug('ATTRS = %r', moonshot.authGSSServerAttributes(context['context']))
                expires = datetime.now() + timedelta(hours=24)
                self.destroyClientContext(cid, context['context'])
                return username, expires.isoformat(), self.getUserAttributes(username)
        except (moonshot.KrbError, MoonshotException), err:
            LOG.error(err)
            self.destroyClientContext(cid, context['context'])
        raise exception.CredentialNotFound()

    def getUserAttributes(self, username):
        print "getUserAttributes"
        # identity_api = identity.controllers.User()
        # role_api = identity.controllers.Role()
        # tenant_api = identity.controllers.Tenant()
        # context = {'is_admin': True}

        # validatedAttributes = {'role': [], 'project': None}
        # user = identity_api.get_user_by_name(context, username)['user']

        # # Roles
        # roles = role_api.get_user_roles(context, user['id'], user['tenantId'])
        # for r in roles['roles']:
        #     validatedAttributes['role'].append(r['name'])

        # # Tenant name
        # tenant = tenant_api.get_tenant(context, user['tenantId'])['tenant']
        # if tenant['enabled'] is True:
        #     validatedAttributes['project'] = tenant['name']


        # print self.org_mapping_api.list_org_attributes(context)['org_attributes']
        # return validatedAttributes

        #print roles


def build_response(response):
    resp = webob.Response(content_type='application/json')
    resp.body = json.dumps(response)
    return resp