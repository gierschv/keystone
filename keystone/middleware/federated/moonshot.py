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
from datetime import date, timedelta
import webob.dec
import webob.exc
import json
import platform
import moonshot

LOG = logging.getLogger(__name__)

class RequestIssuingService(object):
    def __init__(self):
        pass

    def __call__(self):
        return None

    def getIdPRequest(self, key, issuer, endpoint):
        LOG.info('IssueRequest')
        resp = {
            'idpRequest': {'negotiation': ''},
            'idpEndpoint': {
                'mechanism': '{1 3 6 1 5 5 15 1 1 18}',
                'serviceName': 'keystone@%s' % platform.node()
            }
        }
        return build_response(resp)

class MoonshotException(Exception):
    pass

# TODO: timeout ctx
class CredentialValidator(object):
    contextes = {}

    def __init__(self):
        pass
    
    def __call__(self):
        return None
        
    def validate(self, req, response, realm_id):
        LOG.debug("CredentialValidator/validate")
        cid = self.clientId(req)
        context = self.getClientContext(cid)
        resp = {}

        try:
            if context is None:
                result, context = moonshot.authGSSServerInit('keystone@%s' % platform.node(), '{1 3 6 1 5 5 15 1 1 18}')
                if result != 1:
                    raise MoonshotException('moonshot.authGSSServerInit returned result %d' % result)
            if 'negotiation' in response:
                if response['negotiation'] is None:
                    response['negotiation'] = ""
                result = moonshot.authGSSServerStep(context, response['negotiation'])
                if result == moonshot.AUTH_GSS_CONTINUE:
                    resp = {'negotiation': moonshot.authGSSServerResponse(context)}
                    self.setClientContext(cid, context)
                else:
                    LOG.debug('USERNAME = %s', moonshot.authGSSServerUserName(context))

        except moonshot.KrbError, err:
            LOG.error('Moonshot error: %r' % err)
            self.destroyClientContext(cid, context)
        except MoonshotException, err:
            LOG.error(err)
            self.destroyClientContext(cid, context)
        LOG.debug('Response: %r', response)
        return resp, None, None
        # return username, expires, self.check_issuers(validatedAttributes, realm_id)

    def clientId(self, req):
        return req.remote_addr + '.' + req.environ['REMOTE_PORT']

    def setClientContext(self, cid, context):
        CredentialValidator.contextes[cid] = {'lastUpdate': date.today(), 'context': context}

    def getClientContext(self, cid):
        if cid in CredentialValidator.contextes:
            return CredentialValidator.contextes[cid]['context']
        return None

    def destroyClientContext(self, cid=None, context=None):
        if cid is not None:
            if cid in CredentialValidator.contextes:
                moonshot.authGSSServerClean(CredentialValidator.contextes.pop(cid)['context'])
        if context is not None:
            moonshot.authGSSServerClean(context)

def build_response(response):
    resp = webob.Response(content_type='application/json')
    resp.body = json.dumps(response)
    return resp

