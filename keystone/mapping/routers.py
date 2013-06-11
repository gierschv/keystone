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

from keystone.common import router
import controllers


def append_v3_routers(mapper, routers):

    routers.append(
        router.Router(controllers.OrgMappingController(),
                      'org_attributes', 'org_attribute'))
    routers.append(
        router.Router(controllers.OrgMappingController(),
                      'org_attribute_sets', 'org_attribute_set'))
    routers.append(
        router.Router(controllers.OsMappingController(),
                      'os_attribute_sets', 'os_attribute_set'))
    routers.append(
        router.Router(controllers.AttributeSetMappingController(),
                      'attribute_set_mappings', 'attribute_set_mapping'))
    routers.append(
        router.Router(controllers.AttributeMappingController(),
                      'attribute_mappings', 'attribute_mapping'))

    mapper.connect('/os_attribute_sets/{os_attribute_set_id}/attributes',
                   controller=controllers.OsMappingController(),
                   action='list_attributes_in_os_set',
                   conditions=dict(method=['GET']))




    mapper.connect('/os_attribute_sets/{os_attribute_set_id}/'
                   + 'projects/{attribute_id}',
                   controller=controllers.OsMappingController(),
                   action='add_project_to_os_set',
                   conditions=dict(method=['PUT']))

    mapper.connect('/os_attribute_sets/{os_attribute_set_id}/'
                   + 'roles/{attribute_id}',
                   controller=controllers.OsMappingController(),
                   action='add_role_to_os_set',
                   conditions=dict(method=['PUT']))

    mapper.connect('/os_attribute_sets/{os_attribute_set_id}/'
                   + 'domains/{attribute_id}',
                   controller=controllers.OsMappingController(),
                   action='add_domain_to_os_set',
                   conditions=dict(method=['PUT']))



    mapper.connect('/os_attribute_sets/{os_attribute_set_id}/'
                   + 'attributes/{attribute_id}',
                   controller=controllers.OsMappingController(),
                   action='remove_attribute_from_os_set',
                   conditions=dict(method=['DELETE']))
    mapper.connect('/os_attribute_sets/{os_attribute_set_id}/'
                   + 'attributes/{attribute_id}',
                   controller=controllers.OsMappingController(),
                   action='check_attribute_in_os_set',
                   conditions=dict(method=['HEAD']))
    mapper.connect('/org_attribute_sets/{org_attribute_set_id}/attributes',
                   controller=controllers.OrgMappingController(),
                   action='list_attributes_in_org_set',
                   conditions=dict(method=['GET']))
    mapper.connect('/org_attribute_sets/{org_attribute_set_id}/'
                   + 'attributes/{attribute_id}',
                   controller=controllers.OrgMappingController(),
                   action='add_attribute_to_org_set',
                   conditions=dict(method=['PUT']))
    mapper.connect('/org_attribute_sets/{org_attribute_set_id}/'
                   + 'attributes/{attribute_id}',
                   controller=controllers.OrgMappingController(),
                   action='check_attribute_in_org_set',
                   conditions=dict(method=['HEAD']))
    mapper.connect('/org_attribute_sets/{org_attribute_set_id}/'
                   + 'attributes/{attribute_id}',
                   controller=controllers.OrgMappingController(),
                   action='remove_attribute_from_org_set',
                   conditions=dict(method=['DELETE']))

    mapper.connect('/org_attributes/{org_attribute_id}/issuers',
                   controller=controllers.OrgMappingController(),
                   action='list_issuers_for_attribute',
                   conditions=dict(method=['GET']))
    mapper.connect('/services/{service_id}/attributes',
                   controller=controllers.OrgMappingController(),
                   action='list_attributes_for_issuer',
                   conditions=dict(method=['GET']))
    mapper.connect('/org_attributes/{org_attribute_id}/'
                   + 'issuers/{service_id}',
                   controller=controllers.OrgMappingController(),
                   action='add_issuer_to_attribute',
                   conditions=dict(method=['PUT']))
    mapper.connect('/org_attributes/{org_attribute_id}/'
                   + 'issuers/{service_id}',
                   controller=controllers.OrgMappingController(),
                   action='remove_issuer_from_attribute',
                   conditions=dict(method=['DELETE']))
    mapper.connect('/org_attributes/{org_attribute_id}/'
                   + 'issuers/{service_id}',
                   controller=controllers.OrgMappingController(),
                   action='check_attribute_can_be_issued',
                   conditions=dict(method=['HEAD']))

    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions',
                   controller=controllers.AdminRolePermissionController(),
                   action='list_admin_role_permissions',
                   conditions=dict(method=['GET']))

    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/roles/{role_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='add_role_permission',
                   conditions=dict(method=['PUT']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/projects/{project_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='add_project_permission',
                   conditions=dict(method=['PUT']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/domains/{domain_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='add_domain_permission',
                   conditions=dict(method=['PUT']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/idps/{service_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='add_idp_permission',
                   conditions=dict(method=['PUT']))

    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/roles/{role_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='revoke_role_permission',
                   conditions=dict(method=['DELETE']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/projects/{project_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='revoke_project_permission',
                   conditions=dict(method=['DELETE']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/domains/{domain_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='revoke_domain_permission',
                   conditions=dict(method=['DELETE']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/idps/{service_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='revoke_idp_permission',
                   conditions=dict(method=['DELETE']))

    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/roles/{role_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='check_role_permission',
                   conditions=dict(method=['HEAD']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/projects/{project_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='check_project_permission',
                   conditions=dict(method=['HEAD']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/domains/{domain_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='check_domain_permission',
                   conditions=dict(method=['HEAD']))
    mapper.connect('/admin-role-permissions/{admin_role_id}/permissions/idps/{service_id}',
                   controller=controllers.AdminRolePermissionController(),
                   action='check_idp_permission',
                   conditions=dict(method=['HEAD']))
