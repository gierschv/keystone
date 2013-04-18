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
Created on 1 Feb 2013

@author: Kristy Siu
'''

import logging
import urlparse
import sys
import uuid
from keystone import exception
sys.path.insert(0, '../')
import dm.xmlsec.binding as xmlsec
xmlsec.initialize()
from os.path import dirname, basename
from lxml.etree import parse,tostring,fromstring,ElementTree
from time import localtime, strftime, gmtime
import urllib
import webbrowser
import urllib2
import zlib
import base64
import webob.dec
import webob.exc
import json

from keystone import mapping
from keystone import catalog
LOG = logging.getLogger(__name__)

class RequestIssuingService(object):
    def __init__(self):
        self.tmpl_req = """<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID=""
        Version="2.0"
        IssueInstant=""
        AssertionConsumerServiceIndex="0"
        AttributeConsumingServiceIndex="0">
        <saml:Issuer></saml:Issuer>
        <samlp:NameIDPolicy
        AllowCreate="true"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue/>
</Reference>
</SignedInfo>
<SignatureValue/>
<KeyInfo>
<KeyName/>
</KeyInfo>
</Signature>
        </samlp:AuthnRequest>"""

    def getIdPRequest(self,key, issuer, endpoint):
        resp = {}
        resp['idpRequest'] = '?'+self.create_IdpRequest(key, issuer)
        resp['idpEndpoint'] = endpoint
        return valid_Response(resp)

    def sign(self,doc, key):
        node = xmlsec.findNode(doc, xmlsec.dsig("Signature"))
        dsigCtx = xmlsec.DSigCtx()
        signKey = xmlsec.Key.load(key, xmlsec.KeyDataFormatPem, None)
        signKey.name = basename(key)
        dsigCtx.signKey = signKey
        dsigCtx.sign(node)
        return tostring(doc)

    def create_IdpRequest(self,key, issuer):
        time=strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
        id = uuid.uuid4()
        doc = ElementTree(fromstring(self.tmpl_req))
        doc.getroot().set("ID", id.urn)
        doc.getroot().set("IssueInstant", time)
        for node in doc.getroot().iter():
                if node.tag == "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer":
                        node.text = issuer
#        node = xmlsec.findNode(doc, "Issuer")
#       node.text = issuer

        return self.encodeReq(self.sign(doc,key))
    def __call__(self):
        return None

    def deflate(self,data, compresslevel=9):
    	compress = zlib.compressobj(
        compresslevel,        # level: 0-9
        zlib.DEFLATED,        # method: must be DEFLATED
        -zlib.MAX_WBITS,      # window size in bits:
                                  #   -15..-8: negate, suppress header
                                  #   8..15: normal
                                  #   16..30: subtract 16, gzip header
        zlib.DEF_MEM_LEVEL,   # mem level: 1..8/9
        0                     # strategy:
                                  #   0 = Z_DEFAULT_STRATEGY
                                  #   1 = Z_FILTERED
                                  #   2 = Z_HUFFMAN_ONLY
                                  #   3 = Z_RLE
                                  #   4 = Z_FIXED
        )
        deflated = compress.compress(data)
        deflated += compress.flush()
        return deflated

    def inflate(self,data):
        decompress = zlib.decompressobj(
            -zlib.MAX_WBITS  # see above
        )
        inflated = decompress.decompress(data)
        inflated += decompress.flush()
        return inflated
    def encodeReq(self, req):
        req = self.deflate(req)

        req = base64.b64encode(req)

        req = urllib.urlencode({"SAMLRequest": req})

        return req

class Negotiator(object):

    def __init__(self):
        """ do nothing """
        raise exception.NotImplemented()

    def negotiate(self, data):
        """ do nothing """
        raise exception.NotImplemented()
    

class CredentialValidator(object):
    
    def __init__(self):
        self.org_mapping_api = mapping.controllers.OrgMappingController()
        self.mapping_api = mapping.controllers.AttributeMappingController()
        self.catalog_api = catalog.controllers.EndpointV3()
    
    def __call__(self):
        return None
        
    def validate(self, data, realm_id):
        idp_info = self.catalog_api.list_endpoints({'is_admin': True, 'query_string':{'service_id':realm_id, 'interface': 'public'}})
        unique_attribute = idp_info["endpoints"][0].get("identifier_attribute",None)
        resp = urlparse.parse_qsl(data)
        k, v = resp[0]
        try:
            resp = base64.b64decode(v)
            resp = ElementTree(fromstring(resp))
        except TypeError:
            resp = base64.b64decode(v.replace(" ", "+"))
            resp = ElementTree(fromstring(resp))
        atts = {}
        names = []
        for cond in resp.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Conditions"):
            expires = cond.attrib.get("NotOnOrAfter")
	
        for name in resp.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID"):
            names.append(name.text)
	for att in resp.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
	    ats = []
	    for value in att.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"):
	        ats.append(value.text) 
	    atts[att.get("Name")] = ats
	if unique_attribute is not None and atts.get(unique_attribute, None) is not None:
            names = atts.get(unique_attribute)
        return names[0], expires, self.check_issuers(data, atts, realm_id)

    def check_issuers(self, data, atts, realm_id):
        context = {"is_admin": True}
        valid_atts = {}
        for att in atts:
           for val in atts[att]:
               org_atts = self.org_mapping_api.list_org_attributes(context)['org_attributes']
               for org_att in org_atts:
                   if org_att['type'] == att:
                       if org_att['value'] == val or org_att['value'] is None:
                           try:
                               self.org_mapping_api.check_attribute_can_be_issued(context, service_id=realm_id, org_attribute_id=org_att['id'])
                               try:
                                   valid_atts[att].append(val)
                               except:
                                   valid_atts[att] = [val]
                           except exception.NotFound:
                               pass
        return valid_atts

def valid_Response(response):
    resp = webob.Response(content_type='application/json')
    resp.body = json.dumps(response)
    return resp
        
def inflate(data):
        decompress = zlib.decompressobj(
            -zlib.MAX_WBITS  # see above
        )
        inflated = decompress.decompress(data)
        inflated += decompress.flush()
        return inflated
