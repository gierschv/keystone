import uuid
from keystone.openstack.common import jsonutils 
from keystone import identity
from keystone import auth
from keystone import exception
from keystone.common import dependency
from keystone.common import controller
from keystone.common import manager
from keystone.common import logging
from keystone import config

CONF = config.CONF
LOG = logging.getLogger(__name__)

class AdminRolePermissionController(controller.V3Controller):

    def list_admin_role_permissions(self, context, admin_role_id):
        if not context['is_admin']:
            return
        return {"admin_role_permissions":self.mapping_api.list_admin_role_permissions(context,
                                                            admin_role_id)}

    def _add_permission(self, context, admin_role_id, attribute_id, type):
        if not context['is_admin']:
            return
        return self.mapping_api.add_permission(context, admin_role_id, attribute_id, type)

    def add_role_permission(self, context, admin_role_id, role_id):
        return self._add_permission(context, admin_role_id, role_id, 'role')

    def add_idp_permission(self, context, admin_role_id, service_id):
        return self._add_permission(context, admin_role_id, service_id, 'idp')

    def add_project_permission(self, context, admin_role_id, project_id):
        return self._add_permission(context, admin_role_id, project_id, 'project')

    def add_domain_permission(self, context, admin_role_id, domain_id):
        return self._add_permission(context, admin_role_id, domain_id, 'domain')

    def _revoke_permission(self, context, admin_role_id, attribute_id, type):
        if not context['is_admin']:
            return
        return self.mapping_api.revoke_permission(context, admin_role_id, attribute_id, type)

    def revoke_role_permission(self, context, admin_role_id, role_id):
        return self._revoke_permission(context, admin_role_id, role_id, 'role')

    def revoke_project_permission(self, context, admin_role_id, project_id):
        return self._revoke_permission(context, admin_role_id, project_id, 'project')

    def revoke_domain_permission(self, context, admin_role_id, domain_id):
        return self._revoke_permission(context, admin_role_id, domain_id, 'domain')

    def revoke_idp_permission(self, context, admin_role_id, service_id):
        return self._revoke_permission(context, admin_role_id, service_id, 'idp')

    def _check_permission(self, context, admin_role_id, attribute_id, type):
        if not context['is_admin']:
            return
        return self.mapping_api.check_permission(context, admin_role_id, attribute_id, type)

    def check_role_permission(self, context, admin_role_id, role_id):
        return self._check_permission(context, admin_role_id, role_id, 'role')

    def check_project_permission(self, context, admin_role_id, project_id):
        return self._check_permission(context, admin_role_id, project_id, 'project')

    def check_domain_permission(self, context, admin_role_id, domain_id):
        return self._check_permission(context, admin_role_id, domain_id, 'domain')

    def check_service_permission(self, context, admin_role_id, service_id):
        return self._check_permission(context, admin_role_id, service_id, 'idp')


class AttributeSetMappingController(controller.V3Controller):
    # Sets
    def get_attribute_set_mapping(self, context, attribute_set_mapping_id):
        if not is_authorised(context):
            self.assert_admin(context)
        mapping_id = attribute_set_mapping_id
        mapping = is_permitted(context, self.mapping_api.get_attribute_set_mapping(context,
                                                             mapping_id))
        if not mapping:
            raise exception.ForbiddenAction("You are not authorised to access one or more attribute in this set")
            return
        return {'attribute_set_mapping': mapping}

    def list_attribute_set_mappings(self, context):
        if not is_authorised(context):
            self.assert_admin(context)
        return {'attribute_set_mappings':
                filter_by_user_role(context, self.mapping_api.list_attribute_set_mappings(context))}

    def delete_attribute_set_mapping(self, context, attribute_set_mapping_id):
        if not is_authorised(context):
            self.assert_admin(context)
        mapping_id = attribute_set_mapping_id
        mapping = is_permitted(context, self.mapping_api.get_attribute_set_mapping(context,
                                                             mapping_id))
        if not mapping:
            raise exception.ForbiddenAction("You are not authorised to access one or more attribute in this set")
            return
        self.mapping_api.delete_attribute_set_mapping(context,
                                                      attribute_set_mapping_id)

    def create_attribute_set_mapping(self, context, attribute_set_mapping):
        self.assert_admin(context)
        mapping_id = uuid.uuid4().hex
        mapping_ref = attribute_set_mapping.copy()
        mapping_ref['id'] = mapping_id
        is_permitted(context, mapping_ref)
        new_mapping_ref = self.mapping_api.create_attribute_set_mapping(
            context, mapping_id, mapping_ref)
        return {'attribute_set_mapping': new_mapping_ref}


class AttributeMappingController(controller.V3Controller):
    # Sets
    def _get_attribute_mapping(self, context, mapping):
        attribute_mapping = {}
        attribute_mapping["id"] = mapping["id"]
        org_set = self.mapping_api.get_org_attribute_set(
            context, mapping["org_attribute_set_id"])
        attribute_mapping["org_attribute_set"] = org_set
        attributes = self.mapping_api.list_attributes_in_org_set(
            context, org_set["id"])
        org_set["attributes"] = attributes
        os_set = self.mapping_api.get_os_attribute_set(
            context, mapping["os_attribute_set_id"])
        attribute_mapping["os_attribute_set"] = os_set
        attributes2 = self.mapping_api.list_attributes_in_os_set(
            context, os_set["id"])
        os_set["attributes"] = attributes2
        return attribute_mapping

    def get_attribute_mapping(self, context, attribute_mapping_id):
        mapping_id = attribute_mapping_id
        mapping = self.mapping_api.get_attribute_set_mapping(context,
                                                             mapping_id)
        is_permitted(mapping)
        return {'attribute_mapping': self._get_attribute_mapping(context,
                                                                 mapping)}

    def list_attribute_mappings(self, context):
        attribute_mappings = {}
        mappings_list = []
        mappings = self.mapping_api.list_attribute_set_mappings(context)
        for mapping in mappings:
            attribute_mapping = self._get_attribute_mapping(context,
                                                            mapping)
            mappings_list.append(attribute_mapping)
        attribute_mappings["attribute_mappings"] = filter_by_user_role(context, mappings_list)
        return attribute_mappings

    def delete_attribute_mapping(self, context, attribute_mapping_id):
        mapping_id = attribute_mapping_id
        mapping = self.mapping_api.get_attribute_set_mapping(context,
                                                             mapping_id)
        is_permitted(mapping)
        self.mapping_api.delete_attribute_set_mapping(context,
                                                      attribute_mapping_id)

    def create_attribute_mapping(self, context, attribute_mapping):
        if not context.get("is_admin", None):
            is_permitted(context, attribute_mapping)        
        # Create the org set
        org_attribute_set = {}
        org_set_id = uuid.uuid4().hex
        org_attribute_set["id"] = org_set_id
        name = attribute_mapping["org_attribute_set"]["name"]
        org_attribute_set["name"] = name
        if attribute_mapping["org_attribute_set"].get("description", None) is not None:
            description = attribute_mapping["org_attribute_set"]["description"]
            org_attribute_set["description"] = description
        org_set = self.mapping_api.create_org_attribute_set(context,
                                                            org_set_id,
                                                            org_attribute_set)
        # Add the attributes
        for attribute in attribute_mapping["org_attribute_set"]["attributes"]:
            self.mapping_api.add_attribute_to_org_set(context,
                                                      org_set["id"],
                                                      attribute)
        # Create the os set
        os_attribute_set = {}
        os_set_id = uuid.uuid4().hex
        os_attribute_set["id"] = os_set_id
        name = attribute_mapping["os_attribute_set"]["name"]
        os_attribute_set["name"] = name
        if attribute_mapping["os_attribute_set"].get("description", None) is not None:
            description = attribute_mapping["os_attribute_set"]["description"]
            os_attribute_set["description"] = description
        os_set = self.mapping_api.create_os_attribute_set(context,
                                                          os_set_id,
                                                          os_attribute_set)
        # Add the attributes
        attributes = attribute_mapping["os_attribute_set"]["attributes"]
        for att in attributes:
            attribute, type = att.popitem()
            self.mapping_api.add_attribute_to_os_set(context,
                                                     os_set["id"],
                                                     attribute, type)
        # Create the mapping
        mapping_id = uuid.uuid4().hex
        mapping_ref = {"org_attribute_set_id": org_set["id"],
                       "os_attribute_set_id": os_set["id"]}
        mapping_ref['id'] = mapping_id
        new_mapping_ref = self.mapping_api.create_attribute_set_mapping(
            context, mapping_id, mapping_ref)
        mapping = self.mapping_api.get_attribute_set_mapping(context,
                                                             mapping_id)
        return {'attribute_mapping': self._get_attribute_mapping(context,
                                                                 mapping)}

    def map(self, context, attributes=None):
        org_mapping_api = OrgMappingController()
        # Convert type=value attributes into IDs
        att_ids = []
        for att in attributes:
           for val in attributes[att]:
               org_atts = org_mapping_api.list_org_attributes(context)['org_attributes']
               for org_att in org_atts:
                   if org_att['type'] == att:
                       if org_att['value'] == val or org_att['value'] is None:
                           if not org_att['id'] in att_ids:
                               att_ids.append(org_att['id'])
        matched_sets = []
        for a_id in att_ids:
            set_ids = self.mapping_api.list_org_sets_containing_attribute(context, org_attribute_id=a_id)
            for  s in set_ids:
                all_atts = [ss['id'] for ss in self.mapping_api.list_attributes_in_org_set(context, org_attribute_set_id=s['id'])]
                if set(all_atts) <= set(att_ids):
                    if not s['id'] in matched_sets:
                        matched_sets.append(s['id'])
        all_mappings = self.list_attribute_mappings(context)['attribute_mappings']
        valid_mappings = []
        for m in matched_sets:
            for am in all_mappings:
                if am['org_attribute_set']['id'] == m:
                    valid_mappings.append(am['os_attribute_set']['attributes'])
        return {'attribute_mappings': valid_mappings}

class OrgMappingController(controller.V3Controller):

    # Sets

    def list_org_attribute_sets(self, context):
        return {'org_attribute_sets':
                self.mapping_api.list_org_attribute_sets(context)}

    def get_org_attribute_set(self, context, org_attribute_set_id):
        set_id = org_attribute_set_id
        org_set = self.mapping_api.get_org_attribute_set(context,
                                                         set_id)
        return {'org_attribute_set': org_set}

    def delete_org_attribute_set(self, context, org_attribute_set_id):
        set_id = org_attribute_set_id
        mappings = self.mapping_api.list_attribute_set_mappings(
            context,
            org_attribute_set_id=set_id)
        for mapping in mappings:
            self.mapping_api.delete_attribute_set_mapping(context,
                                                          mapping['id'])
        links = self.mapping_api.list_attributes_in_org_set(context,
                                                            set_id)
        for att in links:
            self.remove_attribute_from_org_set(context,
                                               set_id,
                                               att)
        self.mapping_api.delete_org_attribute_set(context,
                                                  set_id)

    def create_org_attribute_set(self, context, org_attribute_set):
        self.assert_admin(context)
        set_id = uuid.uuid4().hex
        set_ref = org_attribute_set.copy()
        set_ref['id'] = set_id
        new_set_ref = self.mapping_api.create_org_attribute_set(
            context, set_id, set_ref)
        return {'org_attribute_set': new_set_ref}

    def add_attribute_to_org_set(self, context, org_attribute_set_id,
                                 attribute_id):
        return self.mapping_api.add_attribute_to_org_set(context,
                                                         org_attribute_set_id,
                                                         attribute_id)

    def remove_attribute_from_org_set(self, context,
                                      org_attribute_set_id, attribute_id):
        set_id = org_attribute_set_id
        return self.mapping_api.remove_attribute_from_org_set(context,
                                                              set_id,
                                                              attribute_id)

    def check_attribute_in_org_set(self, context,
                                   org_attribute_set_id, attribute_id):
        set_id = org_attribute_set_id
        return self.mapping_api.check_attribute_in_org_set(context,
                                                           set_id,
                                                           attribute_id)

    def list_attributes_in_org_set(self, context, org_attribute_set_id):
        return self.mapping_api.list_attributes_in_org_set(
            context, org_attribute_set_id)
    # Attributes

    def get_org_attribute(self, context, org_attribute_id=None):
        att = self.mapping_api.get_org_attribute(context, org_attribute_id)
        return {'org_attribute': att}

    def list_org_attributes(self, context):
        atts = self.mapping_api.list_org_attributes(context)
        return {'org_attributes': atts}

    def delete_org_attribute(self, context, org_attribute_id):
        att_id = org_attribute_id
        issuers = self.list_issuers_for_attribute({"is_admin":True}, org_attribute_id=org_attribute_id)
        if len(issuers) > 0:
            raise exception.ForbiddenAction("This attribute is currently being issued by one or more Identity Providers and cannot be deleted")
        sets = self.mapping_api.list_org_sets_containing_attribute(
            context,
            org_attribute_id=att_id)
        for set in sets:
            self.delete_org_attribute_set(set)
        self.mapping_api.delete_org_attribute(context, att_id)

    def create_org_attribute(self, context, org_attribute):
        if not is_authorised(context):
            self.assert_admin(context)
        attribute_id = uuid.uuid4().hex
        attribute_ref = org_attribute.copy()
        attribute_ref['id'] = attribute_id
        new_attribute_ref = self.mapping_api.create_org_attribute(
            context, attribute_id, attribute_ref)
        return {'org_attribute': new_attribute_ref}

    def list_issuers_for_attribute(self, context, org_attribute_id):
        return self.mapping_api.list_issuers_for_attribute(context,
                                                        org_attribute_id)

    def add_issuer_to_attribute(self, context, org_attribute_id, service_id):
        permissions_api = AdminRolePermissionController()
        authorised = False
        if not context.get("is_admin"):
            roles = get_user_roles(context)
            for role in roles:
                try:
                    permissions_api._check_permission({"is_admin":True}, admin_role_id=role["id"], attribute_id=service_id, type="idp")
                    authorised = True
                except exception.Forbidden:
                    continue
        else:
            authorised = True
        if not authorised:
            raise exception.ForbiddenAction("You are not authorised to modify the issuing policy of this provider")
        return self.mapping_api.add_issuer_to_attribute(context,
                                                        org_attribute_id,
                                                        service_id)

    def check_attribute_can_be_issued(self, context, org_attribute_id, service_id):
        return self.mapping_api.check_attribute_can_be_issued(context,
                                                        org_attribute_id,
                                                        service_id)

    def remove_issuer_from_attribute(self, context, org_attribute_id, service_id):
        return self.mapping_api.remove_issuer_from_attribute(context,
                                                        org_attribute_id,
                                                        service_id)

class OsMappingController(controller.V3Controller):

    # Sets

    def list_attributes_in_os_set(self, context, os_attribute_set_id):
        set_id = os_attribute_set_id
        return self.mapping_api.list_attributes_in_os_set(context,
                                                          set_id)

    def add_role_to_os_set(self, context, os_attribute_set_id, attribute_id):
        identity_api= identity.Manager()
        identity_api.get_role(context, attribute_id)
        set_id = os_attribute_set_id
        return self.mapping_api.add_attribute_to_os_set(context,
                                                        set_id,
                                                        attribute_id,
                                                        'role')

    def add_project_to_os_set(self, context, os_attribute_set_id, attribute_id):
        identity_api= identity.Manager()
        identity_api.get_project(context, attribute_id)
        set_id = os_attribute_set_id
        return self.mapping_api.add_attribute_to_os_set(context,
                                                        set_id,
                                                        attribute_id,
                                                        'project')

    def add_domain_to_os_set(self, context, os_attribute_set_id, attribute_id):
        identity_api= identity.Manager()
        identity_api.get_domain(context, attribute_id)
        set_id = os_attribute_set_id
        return self.mapping_api.add_attribute_to_os_set(context,
                                                        set_id,
                                                        attribute_id,
                                                        'domain')
    def add_attribute_to_os_set(self, context,
                                os_attribute_set_id, attribute_id):
        type = context['query_string']['type']
        if not type:
            msg = "Attribute Type is required"
            raise exception.ValidationError(msg)
        identity_api = identity.Manager()
        if type == 'role':
            identity_api.get_role(context, attribute_id)
        if type == 'project':
            identity_api.get_project(context, attribute_id)
        if type == 'domain':
            identity_api.get_domain(context, attribute_id)
        set_id = os_attribute_set_id
        return self.mapping_api.add_attribute_to_os_set(context,
                                                        set_id,
                                                        attribute_id,
                                                        type)

    def remove_attribute_from_os_set(self, context,
                                     os_attribute_set_id, attribute_id):
        type = context['query_string']['type']
        if not type:
            msg = "Attribute Type is required"
            raise exception.ValidationError(msg)
        set_id = os_attribute_set_id
        return self.mapping_api.remove_attribute_from_os_set(context,
                                                             set_id,
                                                             attribute_id,
                                                             type)

    def check_attribute_in_os_set(self, context,
                                  os_attribute_set_id, attribute_id):
        type = context['query_string']['type']
        if not type:
            msg = "Attribute Type is required"
            raise exception.ValidationError(msg)
        set_id = os_attribute_set_id
        return self.mapping_api.check_attribute_in_os_set(context,
                                                          set_id,
                                                          attribute_id,
                                                          type)

    def get_os_attribute_set(self, context, os_attribute_set_id=None):
        if os_attribute_set_id:
            os_set = self.mapping_api.get_os_attribute_set(context,
                                                           os_attribute_set_id)
            return {'os_attribute_set': os_set}

    def list_os_attribute_sets(self, context):
        return {'os_attribute_sets':
                self.mapping_api.list_os_attribute_sets(context)}

    def delete_os_attribute_set(self, context, os_attribute_set_id):
        mappings = self.mapping_api.list_attribute_set_mappings(
            context,
            os_attribute_set_id=os_attribute_set_id)
        for mapping in mappings:
            self.mapping_api.delete_attribute_set_mapping(context,
                                                          mapping['id'])
        links = self.list_attributes_in_os_set(context, os_attribute_set_id)
        for att, type in links:
            self.remove_attribute_from_os_set(context,
                                              os_attribute_set_id,
                                              att, type)

        self.mapping_api.delete_os_attribute_set(context, os_attribute_set_id)

    def create_os_attribute_set(self, context, os_attribute_set):
        self.assert_admin(context)
        set_id = uuid.uuid4().hex
        set_ref = os_attribute_set.copy()
        set_ref['id'] = set_id
        new_set_ref = self.mapping_api.create_os_attribute_set(context,
                                                               set_id, set_ref)
        return {'os_attribute_set': new_set_ref}

    def clean_up_os_sets(context, attribute_id, type):
        sets = self.mapping_api.list_os_sets_containing_attribute(
            attribute_id=attribute_id,
            type=type)
        for set in sets:
            self.delete_os_attribute_set(context, set['id'])

def is_authorised(context):
    # VGI
    return True
    # Return true if the user has a role entry in the permissions table
    # Declare apis
    permissions_api = AdminRolePermissionController()
    admin_context = {"is_admin": True}
    for role in get_user_roles(context):
        permissions = permissions_api.list_admin_role_permissions(admin_context, admin_role_id=role["id"])
        if len(permissions["admin_role_permissions"]) > 0:
            return True

def filter_by_user_role(context, mappings):
    new_mappings = []
    for mapping in mappings:
        print "FILTERING"
        try:
            is_permitted(context, mapping)
            new_mappings.append(mapping)
        except exception.Forbidden:
            continue
    return new_mappings

def get_user_roles(context):
    # Return all of the roles this user has across all projects and domains
    project_api = identity.controllers.ProjectV3()
    role_api = identity.controllers.RoleV3()
    domain_api = identity.controllers.DomainV3()
    user_api = identity.controllers.UserV3()
    token_api = auth.controllers.Auth()
    # First get the user details from the token
    if context.get("token_id", None) is None:
        # If the context doesn't contain a token we can't do anything - not authorised
        return False;
    # Context for internal requests
    admin_context = {"is_admin": True}
    # Set up the validate token request
    admin_context["subject_token_id"] = context.get("token_id")
    admin_context["query_string"] = {}
    token_data = token_api.validate_token(admin_context)
    # Now we can get the user_id
    user_id = jsonutils.loads(token_data.body)["token"]["user"]["id"]
    # Get the projects so we can get all the users roles across all projects
    admin_context.pop("subject_token_id")
    admin_context["path"] = ""
    projects = project_api.list_user_projects(admin_context, user_id=user_id)
    for proj in projects["projects"]:
        roles = role_api.list_grants(admin_context, user_id=user_id, project_id=proj["id"])["roles"]
    domains = domain_api.list_domains(admin_context)
    for dom in domains["domains"]:
        dom_roles = role_api.list_grants(admin_context, user_id=user_id, domain_id=dom["id"])["roles"]
    all_roles = []
    for r in roles:
        all_roles.append(r)
    for r in dom_roles:
        all_roles.append(r)
    return all_roles;

def is_permitted(context, mapping):
    # Check if the mapping contains IDs or details
    os_set_api = OsMappingController()
    permissions_api = AdminRolePermissionController()
    # Return the mapping if the admin token has been used
    if context["is_admin"]:
        return mapping
    mapping_ref = mapping.copy()
    if mapping.get("org_attribute_set_id", None) is not None:
        mapping_ref["os_attribute_set"] = os_set_api.get_os_attribute_set({"is_admin": True}, os_attribute_set_id=mapping["os_attribute_set_id"])["os_attribute_set"]
        mapping_ref["os_attribute_set"]["attributes"] = os_set_api.list_attributes_in_os_set({"is_admin":True}, os_attribute_set_id=mapping["os_attribute_set_id"])
    attributes = mapping_ref["os_attribute_set"]["attributes"]
    roles = get_user_roles(context)
    for r in roles:
        print attributes
        for att in attributes:
            att_copy = att.copy()
            k, v = att_copy.popitem()
            permissions_api._check_permission({"is_admin":True},admin_role_id=r["id"], attribute_id=k, type=v)
    return mapping
