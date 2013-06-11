import functools
from keystone.mapping import Driver
from keystone.common import sql
from keystone.identity.backends import sql as identity
from keystone import exception


class Mapping(sql.Base, Driver):

    # Organisational
    #Sets
    def create_org_attribute_set(self, org_attribute_set_id,
                                 org_attribute_set_ref):
        session = self.get_session()
        with session.begin():
            orgset = OrgAttributeSet.from_dict(org_attribute_set_ref)
            session.add(orgset)
            session.flush()
        return orgset.to_dict()

    def get_org_attribute_set(self, set_id):
        session = self.get_session()
        ref = self._get_org_attribute_set(session, set_id).to_dict()
        return ref

    def _get_org_attribute_set(self, session, set_id):
        try:
            return session.query(OrgAttributeSet).filter_by(
                id=set_id).one()
        except sql.NotFound:
            raise exception.OrgAttributeSetNotFound(
                org_attribute_set_id=set_id)

    def list_org_attribute_sets(self):
        session = self.get_session()
        sets = session.query(OrgAttributeSet)
        sets = sets.all()
        return [s.to_dict() for s in list(sets)]

    def delete_org_attribute_set(self, set_id):
        session = self.get_session()
        with session.begin():
            ref = self._get_org_attribute_set(session, set_id)
            session.query(OrgAttributeAssociation).filter_by(
                org_attribute_set_id=set_id).delete()
            session.delete(ref)
            session.flush()

    # Attributes
    def create_org_attribute(self, context, org_att_ref):
        session = self.get_session()
        with session.begin():
            attribute = OrgAttribute.from_dict(org_att_ref)
            session.add(attribute)
            session.flush()
        return attribute.to_dict()

    def get_org_attribute(self, attribute_id):
        session = self.get_session()
        return self._get_org_attribute(session, attribute_id).to_dict()

    def _get_org_attribute(self, session, attribute_id):
        try:
            return session.query(OrgAttribute).filter_by(
                id=attribute_id).one()
        except sql.NotFound:
            raise exception.OrgAttributeNotFound(org_attribute_id=attribute_id)

    def list_org_attributes(self):
        session = self.get_session()
        attributes = session.query(OrgAttribute).all()
        return [s.to_dict() for s in list(attributes)]

    def delete_org_attribute(self, attribute_id):
        session = self.get_session()
        with session.begin():
            ref = self._get_org_attribute(session, attribute_id)
            session.query(OrgAttributeAssociation).filter_by(
                org_attribute_id=attribute_id).delete()
            session.delete(ref)
            session.flush()

    def add_issuer_to_attribute(self, org_attribute_id,
                                 service_id):
        session = self.get_session()
        self.get_org_attribute(org_attribute_id)
        #self.get_service(service_id)
        query = session.query(OrgAttributeIdpMembership)
        query = query.filter_by(
            org_attribute_id=org_attribute_id)
        query = query.filter_by(service_id=service_id)
        existing = query.first()
        if existing:
            return
        with session.begin():
            assoc = OrgAttributeIdpMembership(
                org_attribute_id=org_attribute_id,
                service_id=service_id)
            session.add(assoc)
            session.flush()

    def check_attribute_can_be_issued(self, org_attribute_id,
                                 service_id):
        session = self.get_session()
        self.get_org_attribute(org_attribute_id)
        #self.get_service(service_id)
        query = session.query(OrgAttributeIdpMembership)
        query = query.filter_by(
            org_attribute_id=org_attribute_id)
        query = query.filter_by(service_id=service_id)
        existing = query.first()
        if not existing:
            raise exception.NotFound("Attribute cannot be issued")
        session.flush()

    def list_issuers_for_attribute(self, org_attribute_id):
        session = self.get_session()
        self.get_org_attribute(org_attribute_id)
        #self.get_service(service_id)
        query = session.query(OrgAttributeIdpMembership)
        query = query.filter_by(
            org_attribute_id=org_attribute_id)
        qs = query.all()
        return [q.service_id for q in qs]

    def remove_issuer_from_attribute(self, org_attribute_id,
                                     service_id):
        session = self.get_session()
        self.get_org_attribute(org_attribute_id)
        #self.get_service(service_id)
        query = session.query(OrgAttributeIdpMembership)
        query = query.filter_by(
            org_attribute_id=org_attribute_id)
        query = query.filter_by(service_id=service_id)
        existing = query.first()
        if not existing:
            raise exception.NotFound("Attribute cannot be issued")
        query.delete()
        session.flush()

    def list_attributes_in_org_set(self, org_attribute_set_id):
        session = self.get_session()
        self.get_org_attribute_set(org_attribute_set_id)
        query = session.query(OrgAttributeAssociation)
        query = query.filter_by(
            org_attribute_set_id=org_attribute_set_id)
        qs = list(query.all())
        session.flush()
        return [self.get_org_attribute(q.org_attribute_id) for q in qs]

    def list_org_sets_containing_attribute(self, org_attribute_id):
        session = self.get_session()
        self.get_org_attribute(org_attribute_id)
        query = session.query(OrgAttributeAssociation)
        query = query.filter_by(
            org_attribute_id=org_attribute_id)
        qs = list(query.all())
        session.flush()
        return [self.get_org_attribute_set(q.org_attribute_set_id) for q in qs]

    def check_attribute_in_org_set(self, org_attribute_set_id,
                                   attribute_id):
        session = self.get_session()
        self.get_org_attribute_set(org_attribute_set_id)
        self.get_org_attribute(attribute_id)
        query = session.query(OrgAttributeAssociation)
        query = query.filter_by(
            org_attribute_set_id=org_attribute_set_id)
        query = query.filter_by(org_attribute_id=attribute_id)
        existing = query.first()
        if not existing:
            raise exception.NotFound("Attribute not member of set")
        session.flush()

    def remove_attribute_from_org_set(self, org_attribute_set_id,
                                      attribute_id):
        session = self.get_session()
        self.get_org_attribute_set(org_attribute_set_id)
        self.get_org_attribute(attribute_id)
        query = session.query(OrgAttributeAssociation)
        query = query.filter_by(
            org_attribute_set_id=org_attribute_set_id)
        query = query.filter_by(org_attribute_id=attribute_id)
        existing = query.first()
        if not existing:
            raise exception.NotFound("Attribute not member of set")
        query.delete()
        session.flush()

    def add_attribute_to_org_set(self, org_attribute_set_id,
                                 attribute_id):
        session = self.get_session()
        self.get_org_attribute_set(org_attribute_set_id)
        self.get_org_attribute(attribute_id)
        query = session.query(OrgAttributeAssociation)
        query = query.filter_by(
            org_attribute_set_id=org_attribute_set_id)
        query = query.filter_by(org_attribute_id=attribute_id)
        existing = query.first()
        if existing:
            return
        with session.begin():
            assoc = OrgAttributeAssociation(
                org_attribute_set_id=org_attribute_set_id,
                org_attribute_id=attribute_id)
            session.add(assoc)
            session.flush()

    # Openstack
    #Sets
    def create_os_attribute_set(self, context, os_set_ref):
        session = self.get_session()
        with session.begin():
            osset = OsAttributeSet.from_dict(os_set_ref)
            session.add(osset)
            session.flush()
        return osset.to_dict()

    def get_os_attribute_set(self, set_id):
        session = self.get_session()
        ref = self._get_os_attribute_set(session, set_id).to_dict()
        return ref

    def _get_os_attribute_set(self, session, set_id):
        try:
            return session.query(OsAttributeSet).filter_by(
                id=set_id).one()
        except sql.NotFound:
            raise exception.OsAttributeSetNotFound(set_id=set_id)

    def list_os_attribute_sets(self):
        session = self.get_session()
        sets = session.query(OsAttributeSet)
        sets = sets.all()
        return [s.to_dict() for s in list(sets)]

    def delete_os_attribute_set(self, set_id):
        session = self.get_session()
        with session.begin():
            ref = self._get_os_attribute_set(session, set_id)
            session.query(OsAttributeAssociation).filter_by(
                os_attribute_set_id=set_id).delete()
            session.delete(ref)
            session.flush()

    def _get_os_attribute_set_details(self, session, set_id):
        links = session.query(OsAttributeAssociation).filter_by(
            os_attribute_set_id=set_id).all()
        return [(self._get_os_attribute(
            session, s.attribute_id, s.type)) for s in list(links)]

    # Associations

    def list_attributes_in_os_set(self, os_attribute_set_id):
        session = self.get_session()
        assocs = session.query(OsAttributeAssociation)
        assocs = assocs.filter_by(os_attribute_set_id=os_attribute_set_id)
        return [{s.attribute_id: s.type} for s in list(assocs)]

    def list_os_sets_containing_attribute(self, attribute_id):
        session = self.get_session()
        assocs = session.query(OsAttributeAssociation)
        assocs = assocs.filter_by(attribute_id=attribute_id)
        session.flush()
        return [s.id for s in list(assocs)]

    def check_attribute_in_os_set(self, os_attribute_set_id,
                                  attribute_id, type):
        session = self.get_session()
        self.get_os_attribute_set(os_attribute_set_id)
        query = session.query(OsAttributeAssociation)
        query = query.filter_by(
            os_attribute_set_id=os_attribute_set_id)
        query = query.filter_by(attribute_id=attribute_id)
        query = query.filter_by(type=type)
        existing = query.first()
        if not existing:
            raise exception.NotFound("Attribute not member of set")
        session.flush()

    def remove_attribute_from_os_set(self, os_attribute_set_id,
                                     attribute_id, type):
        session = self.get_session()
        self.get_os_attribute_set(os_attribute_set_id)
        query = session.query(OsAttributeAssociation)
        query = query.filter_by(
            os_attribute_set_id=os_attribute_set_id)
        query = query.filter_by(attribute_id=attribute_id)
        query.filter_by(type=type)
        existing = query.first()
        if not existing:
            raise exception.NotFound("Attribute not member of set")
        query.delete()
        session.flush()

    def add_attribute_to_os_set(self, os_attribute_set_id,
                                attribute_id, type):
        session = self.get_session()
        self.get_os_attribute_set(os_attribute_set_id)
        query = session.query(OsAttributeAssociation)
        query = query.filter_by(
            os_attribute_set_id=os_attribute_set_id)
        query = query.filter_by(attribute_id=attribute_id)
        query = query.filter_by(type=type)
        existing = query.first()
        if existing:
            return
        with session.begin():
            assoc = OsAttributeAssociation(
                os_attribute_set_id=os_attribute_set_id,
                attribute_id=attribute_id, type=type)
            session.add(assoc)
            session.flush()


    # Permissions
    def add_permission(self, admin_role_id, attribute_id, type):
        session = self.get_session()
        query = session.query(AdminRolePermission)
        query = query.filter_by(
            admin_role_id=admin_role_id)
        query = query.filter_by(attribute_id=attribute_id)
        query = query.filter_by(type=type)
        existing = query.first()
        if existing:
            return
        with session.begin():
            assoc = AdminRolePermission(
                admin_role_id=admin_role_id,
                attribute_id=attribute_id, type=type)
            session.add(assoc)
            session.flush()

    def check_permission(self, admin_role_id, attribute_id, type):
        session = self.get_session()
        query = session.query(AdminRolePermission)
        query = query.filter_by(
            admin_role_id=admin_role_id)
        query = query.filter_by(attribute_id=attribute_id)
        query = query.filter_by(type=type)
        existing = query.first()
        if not existing:
            raise exception.Forbidden("Permission denied for attribute "+attribute_id)
        session.flush()

    def revoke_permission(self, admin_role_id, attribute_id, type):
        session = self.get_session()
        query = session.query(AdminRolePermission)
        query = query.filter_by(
            admin_role_id=admin_role_id)
        query = query.filter_by(attribute_id=attribute_id)
        query = query.filter_by(type=type)
        existing = query.first()
        if not existing:
            raise exception.NotFound("No permission found to revoke")
        query.delete()
        session.flush()

    def list_admin_role_permissions(self, admin_role_id):
        session = self.get_session()
        assocs = session.query(AdminRolePermission)
        assocs = assocs.filter_by(admin_role_id=admin_role_id)
        return [{s.attribute_id: s.type} for s in list(assocs)]

    # Attribute Mapping
    def create_attribute_set_mapping(self, context, mapping_ref):
        session = self.get_session()
        with session.begin():
            mapping = AttributeMapping.from_dict(mapping_ref)
            session.add(mapping)
            session.flush()
        return mapping.to_dict()

    def get_attribute_set_mapping(self, attribute_set_mapping_id):
        session = self.get_session()
        ref = self._get_attribute_set_mapping(session,
                                              attribute_set_mapping_id)
        ref = ref.to_dict()
        return ref

    def _get_attribute_set_mapping(self, session, mapping_id):
        try:
            return session.query(AttributeMapping).filter_by(
                id=mapping_id).one()
        except sql.NotFound:
            raise exception.MappingNotFound(id=mapping_id)

    def delete_attribute_set_mapping(self, mapping_id):
        session = self.get_session()
        with session.begin():
            ref = self._get_attribute_set_mapping(session, mapping_id)
            session.delete(ref)
            session.flush()

    def list_attribute_set_mappings(self, org_attribute_set_id=None,
                                    os_attribute_set_id=None):
        session = self.get_session()
        mappings = session.query(AttributeMapping)
        if org_attribute_set_id:
            mappings = mappings.filter_by(
                org_attribute_set_id=org_attribute_set_id)
        if os_attribute_set_id:
            mappings = mappings.filter_by(
                os_attribute_set_id=os_attribute_set_id)
        mappings = mappings.all()
        return [self.get_attribute_set_mapping(m.id) for m in list(mappings)]


class OrgAttributeSet(sql.ModelBase, sql.DictBase):
    __tablename__ = 'org_attribute_set'
    attributes = ['id']
    id = sql.Column(sql.String(64), primary_key=True)
    extra = sql.Column(sql.JsonBlob())


class OrgAttribute(sql.ModelBase, sql.DictBase):
    __tablename__ = 'org_attribute'
    attributes = ['id', 'type', 'value']
    id = sql.Column(sql.String(64), primary_key=True)
    type = sql.Column(sql.String(255))
    value = sql.Column(sql.String(255))
    extra = sql.Column(sql.JsonBlob())

class OrgAttributeIdpMembership(sql.ModelBase, sql.DictBase):
    __tablename__ = 'org_attribute_idp_membership'
    org_attribute_id = sql.Column(
        sql.String(64), sql.ForeignKey('org_attribute.id'), primary_key=True)
    service_id = sql.Column(
        sql.String(64),  sql.ForeignKey('service.id'),
        primary_key=True)

class OrgAttributeAssociation(sql.ModelBase, sql.DictBase):
    __tablename__ = 'org_attribute_association'
    org_attribute_id = sql.Column(
        sql.String(64), sql.ForeignKey('org_attribute.id'), primary_key=True)
    org_attribute_set_id = sql.Column(
        sql.String(64),  sql.ForeignKey('org_attribute_set.id'),
        primary_key=True)


class OsAttributeSet(sql.ModelBase, sql.DictBase):
    __tablename__ = 'os_attribute_set'
    attributes = ['id']
    id = sql.Column(sql.String(64), primary_key=True)
    extra = sql.Column(sql.JsonBlob())


class OsAttributeAssociation(sql.ModelBase, sql.DictBase):
    __tablename__ = 'os_attribute_association'
    attribute_id = sql.Column(sql.String(64), primary_key=True)
    os_attribute_set_id = sql.Column(
        sql.String(64),  sql.ForeignKey('os_attribute_set.id'),
        primary_key=True)
    type = sql.Column(sql.String(255), primary_key=True)


class AttributeMapping(sql.ModelBase, sql.DictBase):
    __tablename__ = 'attribute_mapping'
    attributes = ['id', 'org_attribute_set_id', 'os_attribute_set_id']
    id = sql.Column(sql.String(64), primary_key=True)
    org_attribute_set_id = sql.Column(
        sql.String(64),  sql.ForeignKey('org_attribute_set.id'))
    os_attribute_set_id = sql.Column(
        sql.String(64),  sql.ForeignKey('os_attribute_set.id'))
    extra = sql.Column(sql.JsonBlob())


class AdminRolePermission(sql.ModelBase, sql.DictBase):
    __tablename__ = 'admin_role_perm'
    attribute_id = sql.Column(sql.String(64), primary_key=True)
    admin_role_id = sql.Column(
        sql.String(64),  sql.ForeignKey('os_attribute_set.id'),
        primary_key=True)
    type = sql.Column(sql.String(255), primary_key=True)
