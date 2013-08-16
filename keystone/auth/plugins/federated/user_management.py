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

    def manage(self, username):
        # Create User
        sha1 = hashlib.sha1()
        sha1.update(username)
        new_id = sha1.hexdigest()
        tempPass = temp_password
        user_ref = {'id': new_id, 'name': new_id, 'password': tempPass}
        try:
            user = self.identity_api.create_user({'is_admin': True}, user=user_ref)['user']
            # return user, tempPass
        except exception.Conflict:
            users = self.identity_api.list_users({"is_admin": True, "query_string":{}, "path":""})
            for u in users["users"]:
                if new_id == u["name"]:
                    user = u
        # Return user
        return user["id"]