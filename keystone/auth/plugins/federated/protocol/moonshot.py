'''
Created on 13 Jun 2013

@author: Vincent Giersch

'''

from datetime import date, datetime, timedelta
import logging
from lxml.etree import parse, tostring, fromstring, ElementTree
import uuid
import platform
import pymoonshot

from keystone import exception

LOG = logging.getLogger(__name__)


class MoonshotException(Exception):
    pass


class Moonshot(object):
    # GSS contexts
    contexts = {}

    def __exit__(self, type, value, traceback):
        for cid in Moonshot.contexts.keys():
            LOG.debug('Clean GSSAPI context: %s', cid)
            self.destroyClientContext(cid)

    def setClientContext(self, cid, context):
        # TODO: add to conf file
        context['expires'] = datetime.now() + timedelta(seconds=60)
        Moonshot.contexts[cid] = context

    def getClientContext(self, cid):
        self.cleanExpiredContextes()
        if cid in Moonshot.contexts:
            return Moonshot.contexts[cid]
        return None

    def cleanExpiredContextes(self):
        for cid in Moonshot.contexts.keys():
            if Moonshot.contexts[cid]['expires'] < datetime.now():
                LOG.debug('Clean expired GSSAPI context: %s', cid)
                self.destroyClientContext(cid)

    def destroyClientContext(self, cid=None, context=None, clean=True):
        try:
            if cid is not None:
                if cid in Moonshot.contexts:
                    pymoonshot.authGSSServerClean(
                        Moonshot.contexts.pop(cid)['context']
                    )
            if context is not None:
                pymoonshot.authGSSServerClean(context)
            LOG.debug('Remaining contextes: %r' % self.contexts)
        except Exception, err:
            LOG.error('GSS clean error: %s' % err)

    # Plugin steps
    def request_auth(self, auth_payload):
        return {
            'mechanism': '{1 3 6 1 5 5 15 1 1 18}',
            'serviceName': 'keystone@%s' % platform.node()
        }

    def negotiate(self, auth_payload):
        # Client identifier
        if 'cid' in auth_payload and auth_payload['cid'] is not None:
            cid = uuid.UUID(auth_payload['cid']).hex
        else:
            cid = uuid.uuid4().hex

        # Negotiation string
        negotiation = auth_payload.get('negotiation')
        # if not negotiation:
        #     raise exception.ValidationError(attribute='negotiation',
        #                                     target=negotiation)
        if not negotiation:
            raise KeyError('No negotiation payload')

        context = self.getClientContext(cid)
        resp = {'cid': cid, 'negotiation': None}

        try:
            # Init
            if context is None:
                context = {}
                result, context['context'] = pymoonshot.authGSSServerInit(
                    'keystone@%s' % platform.node(),
                    '{1 3 6 1 5 5 15 1 1 18}'
                )
                if result != 1:
                    raise MoonshotException(
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

        except (pymoonshot.KrbError, MoonshotException), err:
            LOG.error(err)
            self.destroyClientContext(cid, context['context'])
            raise exception.CredentialNotFound()

        return resp

    def validate(self, auth_payload):
        # Client identifier
        cid = auth_payload.get('cid')
        if not cid:
            raise exception.ValidationError(
                attribute='cid', target=auth_payload
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

        except (pymoonshot.KrbError, MoonshotException), err:
            LOG.error(err)
            self.destroyClientContext(cid, context['context'])
        raise exception.CredentialNotFound()
