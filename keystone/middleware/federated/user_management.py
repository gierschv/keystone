import time
import uuid
import random
import hashlib
import base64

from keystone import identity
from keystone import exception
from keystone.openstack.common import timeutils
temp_password = str(random.getrandbits(20))
temp_password = str(time.time())+temp_password
sha = hashlib.sha1()
sha.update(temp_password)
temp_password = base64.b64encode(sha.digest())

class UserManager(object):

    def __init__(self):
        self.identity_api = identity.controllers.UserV3()

    def manage(self, username, expires, updatePass=False):
		# Clean up old users
        self.cleanup()
		# Create User
        sha1 = hashlib.sha1()
        sha1.update(username)
        new_id = base64.b64encode(sha1.digest())
        tempPass = temp_password
        user_ref = {'id': new_id, 'name': new_id, 'password': tempPass, 'expires': expires}
        try:
            user = self.identity_api.create_user({'is_admin': True}, user=user_ref)['user']
            return user, tempPass
        except exception.Conflict:
            users = self.identity_api.list_users({"is_admin": True, "query_string":{}, "path":""})
            for u in users["users"]:
                if new_id == u["name"]:
                    user = u
                    if updatePass:
                        user['password'] = tempPass
                    user['expires'] = expires
                    self.identity_api.update_user({"is_admin": True}, user_id=user['id'], user=user) 
		# Return user
            return user, tempPass


    def cleanup(self):
        expired_users = self.identity_api.get_expired_users(context={"is_admin": True})
        for u in expired_users["users"]:
            self.identity_api.delete_user({"is_admin": True},user_id=u["id"]) 
