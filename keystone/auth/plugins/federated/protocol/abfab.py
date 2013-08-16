# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from datetime import date, datetime, timedelta
import logging
from lxml.etree import parse, tostring, fromstring, ElementTree
import uuid
import platform
import pymoonshot

from keystone.common import config
from keystone import exception

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ABFABException(Exception):
    pass


class ABFAB(object):
    # GSS contexts
    contexts = {}

    def __exit__(self, type, value, traceback):
        for cid in ABFAB.contexts.keys():
            LOG.debug('Clean GSSAPI context: %s', cid)
            self.destroyClientContext(cid)

    def setClientContext(self, cid, context):
        timeout = CONF.auth.get('abfab_ctx_timeout')
        context['expires'] = datetime.now() + timedelta(seconds=timeout)
        ABFAB.contexts[cid] = context

    def getClientContext(self, cid):
        self.cleanExpiredContextes()
        if cid in ABFAB.contexts:
            return ABFAB.contexts[cid]
        return None

    def cleanExpiredContextes(self):
        for cid in ABFAB.contexts.keys():
            if ABFAB.contexts[cid]['expires'] < datetime.now():
                LOG.debug('Clean expired GSSAPI context: %s', cid)
                self.destroyClientContext(cid)

    def destroyClientContext(self, cid=None, context=None, clean=True):
        try:
            if cid is not None:
                if cid in ABFAB.contexts:
                    pymoonshot.authGSSServerClean(
                        ABFAB.contexts.pop(cid)['context']
                    )
            if context is not None:
                pymoonshot.authGSSServerClean(context)
            LOG.debug('Remaining contextes: %r' % self.contexts)
        except Exception, err:
            LOG.error('GSS clean error: %s' % err)

    # Plugin steps
    def request_auth(self, protocol_data):
        return {
            'mechanism': '{1 3 6 1 5 5 15 1 1 18}',
            'service_name': 'keystone@%s' % platform.node()
        }

    def negotiate(self, protocol_data):
        # Client identifier
        if 'cid' in protocol_data and protocol_data['cid'] is not None:
            cid = uuid.UUID(protocol_data['cid']).hex
        else:
            cid = uuid.uuid4().hex

        # Negotiation string
        negotiation = protocol_data.get('negotiation')
        if not negotiation:
            raise exception.ValidationError(
                attribute='negotiation', target=protocol_data
            )

        context = self.getClientContext(cid)
        resp = {'cid': cid, 'negotiation': None}

        try:
            # Init
            if context is None:
                context = {}
                result, context['context'] = pymoonshot.authGSSServerInit(
                    'keystone@%s' % platform.node()
                    #'{1 3 6 1 5 5 15 1 1 18}'
                )
                if result != 1:
                    raise ABFABException(
                        'moonshot.authGSSServerInit returned %d' % result
                    )

            # Negotiate steps
            context['state'] = pymoonshot.authGSSServerStep(
                context['context'], negotiation
            )
            self.setClientContext(cid, context)
            resp['negotiation'] = pymoonshot.authGSSServerResponse(
                context['context']
            )

            #LOG.debug('Context = %r'% context)

        except (pymoonshot.KrbError, ABFABException), err:
            LOG.error(err)
            self.destroyClientContext(cid, context['context'])
            raise exception.Unauthorized()

        return resp

    def validate(self, protocol_data):
        # Client identifier
        cid = protocol_data.get('cid')
        if not cid:
            raise exception.ValidationError(
                attribute='cid', target=protocol_data
            )

        context = self.getClientContext(cid)
        try:
            if type(context) == dict and \
                    context['state'] == pymoonshot.AUTH_GSS_COMPLETE:

                attributes = pymoonshot.authGSSServerAttributes(
                    context['context']
                )
                self.destroyClientContext(cid, context['context'])
                LOG.debug('ATTRS = %r', attributes)
                LOG.debug(
                    'SAML assertion = %r',
                    attributes['urn:ietf:params:gss:federated-saml-assertion']
                )

                assertion = ElementTree(fromstring(
                    attributes['urn:ietf:params:gss:federated-saml-assertion']
                ))

                atts = {}
                names = []
                for cond in assertion.iter(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'
                ):
                    expires = cond.attrib.get('NotOnOrAfter')

                for name in assertion.iter(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}NameID'
                ):
                    names.append(name.text)
                for att in assertion.iter(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
                ):
                    ats = []
                    for value in att.iter(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
                    ):
                        ats.append(value.text)
                    atts[att.get('Name')] = ats

                return names[0], atts, expires

        except (pymoonshot.KrbError, ABFABException), err:
            LOG.error(err)
            self.destroyClientContext(cid, context['context'])
        raise exception.Unauthorized()
