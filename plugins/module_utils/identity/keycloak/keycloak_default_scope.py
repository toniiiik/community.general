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

URL_REALM_SCOPES_DEFAULT = "{url}/admin/realms/{realm}/default-default-client-scopes"
URL_REALM_SCOPES_OPTIONAL = "{url}/admin/realms/{realm}/default-optional-client-scopes"
URL_REALM_SCOPE_DEFAULT = "{url}/admin/realms/{realm}/default-default-client-scopes/{scopeid}"
URL_REALM_SCOPE_OPTIONAL = "{url}/admin/realms/{realm}/default-optional-client-scopes/{scopeid}"

URL_CLIENT_SCOPES_DEFAULT = "{url}/admin/realms/{realm}/clients/{clientid}/default-client-scopes"
URL_CLIENT_SCOPES_OPTIONAL = "{url}/admin/realms/{realm}/clients/{clientid}/optional-client-scopes"
URL_CLIENT_SCOPE_DEFAULT = "{url}/admin/realms/{realm}/clients/{clientid}/default-client-scopes/{scopeid}"
URL_CLIENT_SCOPE_OPTIONAL = "{url}/admin/realms/{realm}/clients/{clientid}/optional-client-scopes/{scopeid}"

class KeycloakDefaultScopeAPI(KeycloakAPI):
    """ Keycloak API access; Keycloak uses OAuth 2.0 to protect its API, an access token for which
        is obtained through OpenID connect
    """
    def __init__(self, module, connection_header):
        super().__init__(module, connection_header)

    def get_default_scopes(self, cid, realm="master"):
        """ Get  default scope list for realm or client

        cid is a UUID provided by the Keycloak API
        :param cid: UUID of the client where scope will be set
        :param realm: Realm in which the user resides; default 'master'.
        """
        default_scope_url = URL_REALM_SCOPES_DEFAULT.format(url=self.baseurl, realm=realm)
        if cid is not None:
            default_scope_url = URL_CLIENT_SCOPES_DEFAULT.format(url=self.baseurl, realm=realm, userid=cid)        
        return self.open_url_with_result(default_scope_url, method="GET")

    def get_optional_scopes(self, cid, realm="master"):
        """ Get  default optional scope list for realm or client

        cid is a UUID provided by the Keycloak API
        :param cid: UUID of the client where scope will be set
        :param realm: Realm in which the user resides; default 'master'.
        """
        optional_scope_url = URL_REALM_SCOPES_OPTIONAL.format(url=self.baseurl, realm=realm)
        if cid is not None:
            optional_scope_url = URL_CLIENT_SCOPES_OPTIONAL.format(url=self.baseurl, realm=realm, userid=cid)        
        return self.open_url_with_result(optional_scope_url, method="GET")

    def set_default_scope(self, cid, scopeid,realm="master"):
        """ Set default scope defined for realm or client

        cid is a UUID provided by the Keycloak API
        :param cid: UUID of the client where scope will be set
        :param realm: Realm in which the user resides; default 'master'.
        :param scopeid: Scope id to be set on realm or client.
        """
        default_scope_url = URL_REALM_SCOPE_DEFAULT.format(url=self.baseurl, realm=realm, scopeid=scopeid)
        if cid is not None:
            default_scope_url = URL_CLIENT_SCOPE_DEFAULT.format(url=self.baseurl, realm=realm, userid=cid, scopeid=scopeid)        
        return self.open_url(default_scope_url, method="PUT")

    def set_optional_scope(self, cid, scopeid, realm="master"):
        """ Set default optional scope defined for realm or client

        cid is a UUID provided by the Keycloak API
        :param cid: UUID of the client where scope will be set
        :param realm: Realm in which the user resides; default 'master'.
        :param scopeid: Scope id to be set on realm or client.
        """
        optional_scope_url = URL_REALM_SCOPE_OPTIONAL.format(url=self.baseurl, realm=realm, scopeid=scopeid)
        if cid is not None:
            optional_scope_url = URL_CLIENT_SCOPE_OPTIONAL.format(url=self.baseurl, realm=realm, userid=cid, scopeid=scopeid)        
        return self.open_url(optional_scope_url, method="PUT")


    def delete_default_scope(self, cid, scopeid,realm="master"):
         """ Delete default scope defined for realm or client

        cid is a UUID provided by the Keycloak API
        :param cid: UUID of the client where scope will be deleted.
        :param realm: Realm in which the user resides; default 'master'.
        :param scopeid: Scope id to be deleted.
        """
        default_scope_url = URL_REALM_SCOPE_DEFAULT.format(url=self.baseurl, realm=realm, scopeid=scopeid)
        if cid is not None:
            default_scope_url = URL_CLIENT_SCOPE_DEFAULT.format(url=self.baseurl, realm=realm, userid=cid, scopeid=scopeid)        
        return self.open_url(default_scope_url, method="DELETE")

    def delete_optional_scope(self, cid, scopeid, realm="master"):
        """ Delete default optional scope defined for realm or client

        cid is a UUID provided by the Keycloak API
        :param cid: UUID of the client where scope will be deleted.
        :param realm: Realm in which the user resides; default 'master'.
        :param scopeid: Scope id to be deleted.
        """
        optional_scope_url = URL_REALM_SCOPE_OPTIONAL.format(url=self.baseurl, realm=realm, scopeid=scopeid)
        if cid is not None:
            optional_scope_url = URL_CLIENT_SCOPE_OPTIONAL.format(url=self.baseurl, realm=realm, userid=cid, scopeid=scopeid)        
        return self.open_url_with_result(optional_scope_url, method="DELETE")
