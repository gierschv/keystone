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

import sqlalchemy as sql


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    org_attribute_set = sql.Table(
        'org_attribute_set',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('extra', sql.Text()))

    org_attribute_set.create(migrate_engine, checkfirst=True)

    org_attribute = sql.Table(
        'org_attribute',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('type', sql.String(255)),
        sql.Column('value', sql.String(255)),
        sql.Column('extra', sql.Text()))

    org_attribute.create(migrate_engine, checkfirst=True)

    sql.Table('service', meta, autoload=True)
    org_attribute_idp_membership = sql.Table(
        'org_attribute_idp_membership',
        meta,
        sql.Column(
            'org_attribute_id',
            sql.String(64),
            sql.ForeignKey('org_attribute.id'),
            primary_key=True),
        sql.Column(
            'service_id',
            sql.String(64),
            sql.ForeignKey('service.id'),
            primary_key=True))

    org_attribute_idp_membership.create(migrate_engine, checkfirst=True)

    sql.Table('role', meta, autoload=True)
    admin_role_perm = sql.Table(
        'admin_role_perm',
        meta,
        sql.Column(
            'admin_role_id',
            sql.String(64),
            sql.ForeignKey('org_attribute.id'),
            primary_key=True),
        sql.Column(
            'attribute_id',
            sql.String(64),
            primary_key=True),
        sql.Column(
            'type',
            sql.String(64),
            primary_key=True))

    admin_role_perm.create(migrate_engine, checkfirst=True)

    org_attribute_association = sql.Table(
        'org_attribute_association',
        meta,
        sql.Column(
            'org_attribute_id',
            sql.String(64),
            sql.ForeignKey('org_attribute.id'),
            primary_key=True),
        sql.Column(
            'org_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('org_attribute_set.id'),
            primary_key=True))

    org_attribute_association.create(migrate_engine, checkfirst=True)

    # Openstack attributes
    os_attribute_set = sql.Table(
        'os_attribute_set',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('extra', sql.Text()))

    os_attribute_set.create(migrate_engine, checkfirst=True)

    os_attribute_association = sql.Table(
        'os_attribute_association',
        meta,
        sql.Column(
            'attribute_id',
            sql.String(64),
            nullable=False,
            primary_key=True),
        sql.Column(
            'os_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('os_attribute_set.id'),
            nullable=False,
            primary_key=True),
        sql.Column('type', sql.String(50), primary_key=True))

    os_attribute_association.create(migrate_engine, checkfirst=True)

    # Attribute Mapping
    attribute_mapping = sql.Table(
        'attribute_mapping',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column(
            'os_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('os_attribute_set.id'),
            nullable=False),
        sql.Column(
            'org_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('org_attribute_set.id'),
            nullable=False),
        sql.Column('extra', sql.Text()))

    attribute_mapping.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    org_attribute_set = sql.Table(
        'org_attribute_set',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('extra', sql.Text()))

    org_attribute_set.drop(migrate_engine, checkfirst=True)

    org_attribute = sql.Table(
        'org_attribute',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('type', sql.String(255)),
        sql.Column('value', sql.String(255)),
        sql.Column('extra', sql.Text()))

    org_attribute.drop(migrate_engine, checkfirst=True)

    org_attribute_association = sql.Table(
        'org_attribute_association',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column(
            'org_attribute_id',
            sql.String(64),
            sql.ForeignKey('org_attribute.id'),
            nullable=False),
        sql.Column(
            'org_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('org_attribute_set.id'),
            nullable=False))

    org_attribute_association.drop(migrate_engine, checkfirst=True)

    # Openstack attributes
    os_attribute_set = sql.Table(
        'os_attribute_set',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('extra', sql.Text()))

    os_attribute_set.drop(migrate_engine, checkfirst=True)

    os_attribute_association = sql.Table(
        'os_attribute_association',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column(
            'attribute_id',
            sql.String(64),
            nullable=False),
        sql.Column(
            'os_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('os_attribute_set.id'),
            nullable=False),
        sql.Column('type', sql.String(255)))

    os_attribute_association.drop(migrate_engine, checkfirst=True)

    # Attribute Mapping
    attribute_mapping = sql.Table(
        'attribute_mapping',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column(
            'os_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('os_attribute_set.id'),
            nullable=False),
        sql.Column(
            'org_attribute_set_id',
            sql.String(64),
            sql.ForeignKey('org_attribute_set.id'),
            nullable=False))
    attribute_mapping.drop(migrate_engine, checkfirst=True)
