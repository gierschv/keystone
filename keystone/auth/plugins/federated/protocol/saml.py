'''
Created on 7 Jun 2013

@author: kwss

'''
import urlparse
import base64
import uuid
import zlib
import urllib

from time import strftime, gmtime
from lxml.etree import ElementTree, fromstring, tostring

from keystone import exception
class SAML(object):
    
    def validate(self, auth_payload):
            # Get the validation information
            validation = auth_payload.get("validation")
            if not validation:
                raise exception.ValidationError(attribute="validation", target=auth_payload)
            
            unique_attribute = validation.get("identifier_attribute",None)
            
            assertion = auth_payload.get("assertion")
            if not assertion:
                raise exception.ValidationError(attribute="assertion", target=auth_payload)
            
            assertion = self.parse_response(assertion, validation)
            
            atts = {}
            names = []
            for cond in assertion.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Conditions"):
                expires = cond.attrib.get("NotOnOrAfter")
    
            for name in assertion.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID"):
                names.append(name.text)
            for att in assertion.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
                ats = []
                for value in att.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"):
                    ats.append(value.text)
                atts[att.get("Name")] = ats
            if unique_attribute is not None and atts.get(unique_attribute, None) is not None:
                names = atts.get(unique_attribute)
            return names[0], atts, expires
        
    def check_signature(self, assertion, validation):
        return True
    
    def request_auth(self, details):
        
        endpoint = details.get("endpoint")
        if not endpoint:
            raise exception.ValidationError(attribute="endpoint", target=details)
            
        provider = details.get("provider_id")
        if not provider:
            raise exception.ValidationError(attribute="provider", target=details)
        
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
        return {"endpoint": endpoint, "data": self._create_request(self.tmpl_req, provider), "protocol": "saml", "provider_id": provider}
    
    def _create_request(self, request, provider):
        time=strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())
        new_id = uuid.uuid4()
        doc = ElementTree(fromstring(self.tmpl_req))
        doc.getroot().set("ID", new_id.urn)
        doc.getroot().set("IssueInstant", time)
        for node in doc.getroot().iter():
                if node.tag == "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer":
                        node.text = provider


        return self.encodeReq(tostring(doc))
    
    def deflate(self,data, compresslevel=9):
        compress = zlib.compressobj(
            compresslevel, # level: 0-9
            zlib.DEFLATED, # method: must be DEFLATED
            -zlib.MAX_WBITS, # window size in bits:
                                      # -15..-8: negate, suppress header
                                      # 8..15: normal
                                      # 16..30: subtract 16, gzip header
            zlib.DEF_MEM_LEVEL, # mem level: 1..8/9
            0 # strategy:
                                      # 0 = Z_DEFAULT_STRATEGY
                                      # 1 = Z_FILTERED
                                      # 2 = Z_HUFFMAN_ONLY
                                      # 3 = Z_RLE
                                      # 4 = Z_FIXED
            )
        deflated = compress.compress(data)
        deflated += compress.flush()
        return deflated

    def inflate(self,data):
        decompress = zlib.decompressobj(
            -zlib.MAX_WBITS # see above
        )
        inflated = decompress.decompress(data)
        inflated += decompress.flush()
        return inflated
    def encodeReq(self, req):
        req = self.deflate(req)

        req = base64.b64encode(req)

        req = urllib.urlencode({"SAMLRequest": req})

        return req
    
    def negotiate(self, negotiation):
        raise exception.NotImplemented()
    
    def parse_response(self, assertion, validation):
        resp = urlparse.parse_qsl(assertion)
        k, v = resp[0]
        if not k == "SAMLResponse":
            raise exception.AuthPluginException("SAML protocol module expects URL encoded response:" +
                                                "SAMLResponse=ResponseData") 
        try:
            resp = ElementTree(fromstring(v))
        except Exception as e:
            print e
            try:
                resp = base64.b64decode(v)
                print resp
                resp = ElementTree(fromstring(resp))
            except Exception:
                resp = base64.b64decode(v.replace(" ", "+"))
                print resp
                resp = ElementTree(fromstring(resp))
        if self.check_signature(assertion, validation):
            return resp
        else:
            raise exception.Unauthorized("The signature of the authentication could not be verified")
        