# Copyright (c) 2017, Eike Frost <ei@kefro.st>
#
# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils._text import to_native
from .keycloak import KeycloakAPI, KeycloakError

URL_USERS = "{url}/admin/realms/{realm}/users"
URL_USER = "{url}/admin/realms/{realm}/users/{userid}"
URL_USER_GROUPS = "{url}/admin/realms/{realm}/users/{userid}/groups"
URL_USER_GROUP = "{url}/admin/realms/{realm}/users/{userid}/groups/{groupid}"


class KeycloakUserAPI(KeycloakAPI):
    """ Keycloak API access; Keycloak uses OAuth 2.0 to protect its API, an access token for which
        is obtained through OpenID connect
    """
    def __init__(self, module, connection_header):
        super().__init__(module, connection_header)

    def get_user_by_id(self, uid, realm="master"):
        """ Fetch a keycloak user from the provided realm using the user's unique ID.

        If the group does not exist, None is returned.

        uid is a UUID provided by the Keycloak API
        :param uid: UUID of the user to be returned
        :param realm: Realm in which the user resides; default 'master'.
        """
        users_url = URL_USER.format(url=self.baseurl, realm=realm, userid=uid)
        return self.open_url_with_result(users_url, method="GET")

    def get_user_by_username(self, username, realm="master"):
        """ Fetch a keycloak user within a realm based on its username.

        If the user does not exist, None is returned.
        :param username: Name of the user to fetch.
        :param realm: Realm in which the user resides; default 'master'
        """
        users_url = URL_USERS.format(url=self.baseurl, realm=realm) + '?username=' + username
        users = self.open_url_with_result(users_url, method="GET")
        if len(users)> 0:
            return users[0]

        return None

    def create_user(self, userrep, realm="master"):
        """ Create a Keycloak group.

        :param userrep: a UserRepresentation of the user to be created. Must contain at minimum the field name.
        :return: HTTPResponse object on success
        """
        users_url = URL_USERS.format(url=self.baseurl, realm=realm)
        return self.open_url(users_url, method='POST',
                            data=json.dumps(userrep))

    def update_user(self, userrep, realm="master"):
        """ Update an existing user.

        :param userrep: A UserRepresentation of the updated user.
        :return HTTPResponse object on success
        """
        user_url = URL_USER.format(url=self.baseurl, realm=realm, userid=userrep['id'])
        return self.open_url(user_url, method='PUT',
                        data=json.dumps(userrep))

    def delete_user(self, username=None, userid=None, realm="master"):
        """ Delete a user. One of name or userid must be provided.

        Providing the user ID is preferred as it avoids a second lookup to
        convert a username to an ID.

        :param username: The name of the user. A lookup will be performed to retrieve the user ID.
        :param userid: The ID of the user (preferred to username).
        :param realm: The realm in which this group resides, default "master".
        """

        if userid is None and username is None:
            # prefer an exception since this is almost certainly a programming error in the module itself.
            raise KeycloakError("Unable to delete user - one of user ID or username must be provided.")

        # only lookup the name if groupid isn't provided.
        # in the case that both are provided, prefer the ID, since it's one
        # less lookup.
        if userid is None and username is not None:
            user = self.get_user_by_username(username=username, realm=realm)
            if user is not None:
                userid=user['id']

        # if the group doesn't exist - no problem, nothing to delete.
        if userid is None:
            return None

        # should have a good groupid by here.
        user_url = URL_USER.format(realm=realm, userid=userid, url=self.baseurl)
        return self.open_url(user_url, method='DELETE')
    
    def get_user_groups(self, userid, realm='master'):
        user_group_url = URL_USER_GROUPS.format(url=self.baseurl, realm=realm, userid=userid)
        return self.open_url_with_result(user_group_url, method="GET")

    def add_user_to_group(self, userid, groupid, realm='master'):
        user_group_url = URL_USER_GROUP.format(url=self.baseurl, realm=realm, userid=userid, groupid=groupid)
        return self.open_url(user_group_url, method="PUT")
    
    def delete_user_from_group(self, userid, groupid, realm='master'):
        user_group_url = URL_USER_GROUP.format(url=self.baseurl, realm=realm, userid=userid, groupid=groupid)
        return self.open_url(user_group_url, method="DELETE")