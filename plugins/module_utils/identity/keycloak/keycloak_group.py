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

URL_GROUPS = "{url}/admin/realms/{realm}/groups"
URL_GROUP = "{url}/admin/realms/{realm}/groups/{groupid}"


class KeycloakGroupAPI(KeycloakAPI):
    """ Keycloak API access; Keycloak uses OAuth 2.0 to protect its API, an access token for which
        is obtained through OpenID connect
    """
    def __init__(self, module, connection_header):
        super().__init__(module, connection_header)

    def get_groups(self, realm="master", flatten = False):
        """ Fetch the name and ID of all groups on the Keycloak server.

        To fetch the full data of the group, make a subsequent call to
        get_group_by_groupid, passing in the ID of the group you wish to return.

        :param realm: Return the groups of this realm (default "master").
        """
        groups_url = URL_GROUPS.format(url=self.baseurl, realm=realm)
        all_groups = self.open_url_with_result(groups_url, method="GET")
        if flatten:
            groups=all_groups.copy()
            flat_groups=[]
            while len(groups) > 0:
                subgroups=[]
                for g in groups:
                    subgroups.extend(g.pop('subGroups', []))
                    flat_groups.append(g)
                groups = subgroups
            return flat_groups

        return all_groups

    def get_group_by_groupid(self, gid, realm="master"):
        """ Fetch a keycloak group from the provided realm using the group's unique ID.

        If the group does not exist, None is returned.

        gid is a UUID provided by the Keycloak API
        :param gid: UUID of the group to be returned
        :param realm: Realm in which the group resides; default 'master'.
        """
        groups_url = URL_GROUP.format(url=self.baseurl, realm=realm, groupid=gid)
        return self.open_url_with_result(groups_url, method="GET")

    def get_group_by_name(self, name, realm="master"):
        """ Fetch a keycloak group within a realm based on its name.

        The Keycloak API does not allow filtering of the Groups resource by name.
        As a result, this method first retrieves the entire list of groups - name and ID -
        then performs a second query to fetch the group.

        If the group does not exist, None is returned.
        :param name: Name of the group to fetch.
        :param realm: Realm in which the group resides; default 'master'
        """
        all_groups = self.get_groups(realm=realm)

        for group in all_groups:
            if group['name'] == name:
                return self.get_group_by_groupid(group['id'], realm=realm)

        return None

    def create_group(self, grouprep, realm="master"):
        """ Create a Keycloak group.

        :param grouprep: a GroupRepresentation of the group to be created. Must contain at minimum the field name.
        :return: HTTPResponse object on success
        """
        groups_url = URL_GROUPS.format(url=self.baseurl, realm=realm)
        return self.open_url(groups_url, method='POST', data=json.dumps(grouprep))

    def update_group(self, grouprep, realm="master"):
        """ Update an existing group.

        :param grouprep: A GroupRepresentation of the updated group.
        :return HTTPResponse object on success
        """
        group_url = URL_GROUP.format(url=self.baseurl, realm=realm, groupid=grouprep['id'])
        return self.open_url(group_url, method='PUT', data=json.dumps(grouprep))

    def delete_group(self, name=None, groupid=None, realm="master"):
        """ Delete a group. One of name or groupid must be provided.

        Providing the group ID is preferred as it avoids a second lookup to
        convert a group name to an ID.

        :param name: The name of the group. A lookup will be performed to retrieve the group ID.
        :param groupid: The ID of the group (preferred to name).
        :param realm: The realm in which this group resides, default "master".
        """

        if groupid is None and name is None:
            # prefer an exception since this is almost certainly a programming error in the module itself.
            raise Exception("Unable to delete group - one of group ID or name must be provided.")

        # only lookup the name if groupid isn't provided.
        # in the case that both are provided, prefer the ID, since it's one
        # less lookup.
        if groupid is None and name is not None:
            for group in self.get_groups(realm=realm):
                if group['name'] == name:
                    groupid = group['id']
                    break

        # if the group doesn't exist - no problem, nothing to delete.
        if groupid is None:
            return None

        # should have a good groupid by here.
        group_url = URL_GROUP.format(realm=realm, groupid=groupid, url=self.baseurl)
        return self.open_url(group_url, method='DELETE')