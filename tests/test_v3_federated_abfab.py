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


import platform
import pymoonshot as moonshot
import uuid

from keystone import auth
from keystone import catalog
from keystone import exception
from keystone.common.sql import util as sql_util
from keystone import test
from keystone.auth.plugins.federated import Federated

METHOD_NAME = 'federated'


class TestFederatedABFAB(test.TestCase):
    def setUp(self):
        super(TestFederatedABFAB, self).setUp()

        self.config([
            test.etcdir('keystone.conf.sample'),
            test.testsdir('test_overrides.conf'),
            test.testsdir('backend_sql.conf'),
            test.testsdir('backend_sql_disk.conf'),
            test.testsdir('test_v3_federated_abfab.conf')])

        self.catalog_api = catalog.Manager()

        sql_util.setup_test_database()
        self.load_backends()
        self.load_fixtures()

        self.auth_api = auth.controllers.Auth()
        auth.controllers.AUTH_METHODS[METHOD_NAME] = Federated()

    def tearDown(self):
        sql_util.teardown_test_database()
        super(TestFederatedABFAB, self).tearDown()

    def load_fixtures(self):
        self.service = {
            'id': uuid.uuid4().hex,
            'type': 'idp.abfab',
            'name': 'abfab'
        }
        self.catalog_api.create_service(
            self.service['id'], self.service.copy()
        )

        self.endpoint = {
            'id': uuid.uuid4().hex,
            'service_id': self.service['id'],
            'interface': 'public',
            'url': ''
        }
        self.catalog_api.create_endpoint(
            self.endpoint['id'], self.endpoint.copy()
        )

    def test_missing_phase(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {}
        auth_data = {'identity': auth_data}

        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        with self.assertRaises(exception.AdditionalAuthRequired):
            try:
                self.auth_api.authenticate({}, auth_info, auth_context)
            except exception.AdditionalAuthRequired as e:
                self.assertIn('methods', e.authentication)
                self.assertIn(METHOD_NAME, e.authentication['methods'])
                self.assertIn(METHOD_NAME, e.authentication)
                self.assertEqual(
                    e.authentication[METHOD_NAME],
                    'Federated Requests must specify which stage ' +
                    'of authentication has been reached'
                )
                raise

    def test_discovery_phase(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {'phase': 'discovery'}
        auth_data = {'identity': auth_data}

        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(exception.AdditionalAuthRequired):
            try:
                self.auth_api.authenticate({}, auth_info, auth_context)
            except exception.AdditionalAuthRequired as e:
                self.assertIn('providers', e.authentication[METHOD_NAME])
                self.assertEqual(len(e.authentication[METHOD_NAME]), 1)
                provider = e.authentication[METHOD_NAME]['providers'][0]
                self.assertIn('service', provider)
                self.assertEqual(
                    provider['service']['id'],
                    self.service['id']
                )
                self.assertEqual(
                    provider['service']['name'],
                    self.service['name']
                )
                raise

    def test_request_issuing_phase(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'request',
            'protocol': self.service['name'],
            'protocol_data': {},
            'provider_id': self.service['id']
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(exception.AdditionalAuthRequired):
            try:
                self.auth_api.authenticate({}, auth_info, auth_context)
            except exception.AdditionalAuthRequired as e:
                response = e.authentication[METHOD_NAME]
                self.assertEqual(
                    response['protocol_data']['service_name'],
                    'keystone@%s' % platform.node()
                )
                self.assertEqual(
                    response['protocol_data']['mechanism'],
                    '{1 3 6 1 5 5 15 1 1 18}'
                )
                raise

    def test_negotiation_bad_cid(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'negotiate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {
                'cid': '42'
            }
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(ValueError):
            self.auth_api.authenticate({}, auth_info, auth_context)

    def test_negotiation_missing_negotiation_string(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'negotiate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {
                'cid': None
            }
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(exception.ValidationError):
            self.auth_api.authenticate({}, auth_info, auth_context)

    def test_negotiation_bad_negotiation_token(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'negotiate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {
                'cid': uuid.uuid4().hex,
                'negotiation': uuid.uuid4().hex
            }
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(exception.Unauthorized):
            self.auth_api.authenticate({}, auth_info, auth_context)

    def test_validation_missing_cid(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'validate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {}
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(exception.ValidationError):
            self.auth_api.authenticate({}, auth_info, auth_context)

    def test_validation_bad_cid(self):
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'validate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {
                'cid': '42'
            }
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}

        with self.assertRaises(exception.Unauthorized):
            self.auth_api.authenticate({}, auth_info, auth_context)

    def test_validation_not_completed_authentication(self):
        result, context = moonshot.authGSSClientInit(
            'keystone@%s' % platform.node(),
            0, '{1 3 6 1 5 5 15 1 1 18}'
        )

        moonshot.authGSSClientStep(context, '')
        str_negotiation = moonshot.authGSSClientResponse(context)

        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'negotiate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {
                'cid': None,
                'negotiation': str_negotiation
            }
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        try:
            self.auth_api.authenticate({}, auth_info, auth_context)
        except exception.AdditionalAuthRequired as e:
            cid = e.authentication[METHOD_NAME]['protocol_data']['cid']

            auth_data = {'methods': [METHOD_NAME]}
            auth_data['federated'] = {
                'phase': 'validate',
                'protocol': self.service['name'],
                'provider_id': self.service['id'],
                'protocol_data': {
                    'cid': cid
                }
            }
            auth_data = {'identity': auth_data}
            auth_info = auth.controllers.AuthInfo(None, auth_data)
            with self.assertRaises(exception.Unauthorized):
                self.auth_api.authenticate({}, auth_info, auth_context)

    def test_authentication(self):
        # Negotiation
        gss_flags = moonshot.GSS_C_MUTUAL_FLAG | moonshot.GSS_C_INTEG_FLAG | \
            moonshot.GSS_C_SEQUENCE_FLAG | moonshot.GSS_C_REPLAY_FLAG | \
            moonshot.GSS_C_CONF_FLAG
        result, context = moonshot.authGSSClientInit(
            'keystone@%s' % platform.node(),
            gss_flags,
            '{1 3 6 1 5 5 15 1 1 18}'
        )

        cid = None
        str_negotiation = ''
        gss_status = moonshot.AUTH_GSS_CONTINUE
        while gss_status != moonshot.AUTH_GSS_COMPLETE:
            gss_status = moonshot.authGSSClientStep(
                context, str_negotiation
            )
            str_negotiation = moonshot.authGSSClientResponse(context)

            if str_negotiation is not None:

                auth_data = {'methods': [METHOD_NAME]}
                auth_data['federated'] = {
                    'phase': 'negotiate',
                    'protocol': self.service['name'],
                    'provider_id': self.service['id'],
                    'protocol_data': {
                        'cid': cid,
                        'negotiation': str_negotiation
                    }
                }
                auth_data = {'identity': auth_data}
                auth_info = auth.controllers.AuthInfo(None, auth_data)
                auth_context = {'extras': {}, 'method_names': []}
                with self.assertRaises(exception.AdditionalAuthRequired):
                    try:
                        self.auth_api.authenticate({}, auth_info, auth_context)
                    except exception.AdditionalAuthRequired as e:
                        response = e.authentication[METHOD_NAME]
                        protocol_data = response['protocol_data']
                        self.assertIn('negotiation', protocol_data)
                        self.assertIn('cid', protocol_data)

                        str_negotiation = protocol_data['negotiation']
                        cid = protocol_data['cid']
                        raise

        # Validation
        auth_data = {'methods': [METHOD_NAME]}
        auth_data['federated'] = {
            'phase': 'validate',
            'protocol': self.service['name'],
            'provider_id': self.service['id'],
            'protocol_data': {
                'cid': cid
            }
        }
        auth_data = {'identity': auth_data}
        auth_info = auth.controllers.AuthInfo(None, auth_data)
        auth_context = {'extras': {}, 'method_names': []}
        self.auth_api.authenticate({}, auth_info, auth_context)

        self.assertTrue(len(auth_context['user_id']) > 0)
        self.assertTrue(auth_context['user_id'][0]['enabled'])
