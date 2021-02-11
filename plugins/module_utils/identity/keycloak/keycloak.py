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

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils._text import to_native

URL_TOKEN = "{url}/realms/{realm}/protocol/openid-connect/token"
URL_CLIENT = "{url}/admin/realms/{realm}/clients/{id}"
URL_CLIENT_SECRET = "{url}/admin/realms/{realm}/clients/{id}/client-secret"
URL_CLIENTS = "{url}/admin/realms/{realm}/clients"
URL_CLIENT_ROLES = "{url}/admin/realms/{realm}/clients/{id}/roles"
URL_REALM_ROLES = "{url}/admin/realms/{realm}/roles"

URL_CLIENTTEMPLATE = "{url}/admin/realms/{realm}/client-templates/{id}"
URL_CLIENTTEMPLATES = "{url}/admin/realms/{realm}/client-templates"

URL_CLIENTSCOPE = "{url}/admin/realms/{realm}/client-scopes/{id}"
URL_CLIENTSCOPES = "{url}/admin/realms/{realm}/client-scopes"

URL_REALM = "{url}/admin/realms/{realm}"
URL_REALMS = "{url}/admin/realms"

URL_CLIENT_SCOPE_MAPPINGS = "{url}/admin/realms/{realm}/{target}s/{id}/scope-mappings"
URL_CLIENT_SCOPE_MAPPINGS_CLIENT = "{url}/admin/realms/{realm}/{target}s/{id}/scope-mappings/clients/{client}"
URL_CLIENT_SCOPE_MAPPINGS_CLIENT_AVAILABLE = "{url}/admin/realms/{realm}/{target}s/{id}/scope-mappings/clients/{client}/available"
URL_CLIENT_SCOPE_MAPPINGS_REALM = "{url}/admin/realms/{realm}/{target}s/{id}/scope-mappings/realm"
URL_CLIENT_SCOPE_MAPPINGS_REALM_AVAILABLE = "{url}/admin/realms/{realm}/{target}s/{id}/scope-mappings/realm/available"


def keycloak_argument_spec():
    """
    Returns argument_spec of options common to keycloak_*-modules

    :return: argument_spec dict
    """
    return dict(
        auth_keycloak_url=dict(type='str', aliases=['url'], required=True),
        auth_client_id=dict(type='str', default='admin-cli'),
        auth_realm=dict(type='str', required=True),
        auth_client_secret=dict(type='str', default=None),
        auth_username=dict(type='str', required=True),
        auth_password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=True)
    )


def camel(words):
    return words.split('_')[0] + ''.join(x.capitalize() or '_' for x in words.split('_')[1:])


class KeycloakError(Exception):
    pass


def get_token(base_url, validate_certs, auth_realm, client_id,
              auth_username, auth_password, client_secret):
    auth_url = URL_TOKEN.format(url=base_url, realm=auth_realm)
    temp_payload = {
        'grant_type': 'password',
        'client_id': client_id,
        'client_secret': client_secret,
        'username': auth_username,
        'password': auth_password,
    }
    # Remove empty items, for instance missing client_secret
    payload = dict(
        (k, v) for k, v in temp_payload.items() if v is not None)
    try:
        r = json.loads(to_native(open_url(auth_url, method='POST',
                                          validate_certs=validate_certs,
                                          data=urlencode(payload)).read()))
    except ValueError as e:
        raise KeycloakError(
            'API returned invalid JSON when trying to obtain access token from %s: %s'
            % (auth_url, str(e)))
    except Exception as e:
        raise KeycloakError('Could not obtain access token from %s: %s'
                            % (auth_url, str(e)))

    try:
        return {
            'Authorization': 'Bearer ' + r['access_token'],
            'Content-Type': 'application/json'
        }
    except KeyError:
        raise KeycloakError(
            'Could not obtain access token from %s' % auth_url)
open_url_error_msg = {
    'GET': 'Could not fetch resource',
    'POST': 'Could not create resource',
    'PUT': 'Could not update resource',
    'DELETE': 'Could not delte resource'
}

class KeycloakAPI(object):
    """ Keycloak API access; Keycloak uses OAuth 2.0 to protect its API, an access token for which
        is obtained through OpenID connect
    """
    def __init__(self, module, connection_header):
        self.module = module
        self.baseurl = self.module.params.get('auth_keycloak_url')
        self.validate_certs = self.module.params.get('validate_certs')
        self.restheaders = connection_header

    def open_url(self, url, method, data = None):
        """ Wrapper of open_url

        """
       
        try:
            return open_url(url, method=method, 
                        data=data, 
                        headers=self.restheaders, 
                        validate_certs=self.validate_certs)
        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg="%s %s: %s"
                                          % (open_url_error_msg.get(method, 'Error occured '),url, str(e)))
        except Exception as e:
            self.module.fail_json(msg="%s %s: %s"
                                      % (open_url_error_msg.get(method, 'Error occured '),url, str(e)))
       
    def open_url_with_result(self, url, method, data = None):
        """ Wrapper of open_url

        """
        return json.loads(to_native(self.open_url(url, method=method, data=data).read()))

    def get_clients(self, realm='master', filter=None):
        """ Obtains client representations for clients in a realm

        :param realm: realm to be queried
        :param filter: if defined, only the client with clientId specified in the filter is returned
        :return: list of dicts of client representations
        """
        clientlist_url = URL_CLIENTS.format(url=self.baseurl, realm=realm)
        if filter is not None:
            clientlist_url += '?clientId=%s' % filter

        try:
            return json.loads(to_native(open_url(clientlist_url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain list of clients for realm %s: %s'
                                      % (realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain list of clients for realm %s: %s'
                                      % (realm, str(e)))

    def get_client_by_clientid(self, client_id, realm='master'):
        """ Get client representation by clientId
        :param client_id: The clientId to be queried
        :param realm: realm from which to obtain the client representation
        :return: dict with a client representation or None if none matching exist
        """
        r = self.get_clients(realm=realm, filter=client_id)
        if len(r) > 0:
            return r[0]
        else:
            return None

    def get_client_by_id(self, id, realm='master'):
        """ Obtain client representation by id

        :param id: id (not clientId) of client to be queried
        :param realm: client from this realm
        :return: dict of client representation or None if none matching exist
        """
        client_url = URL_CLIENT.format(url=self.baseurl, realm=realm, id=id)

        try:
            return json.loads(to_native(open_url(client_url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))

        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg='Could not obtain client %s for realm %s: %s'
                                          % (id, realm, str(e)))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain client %s for realm %s: %s'
                                      % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain client %s for realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_id(self, client_id, realm='master'):
        """ Obtain id of client by client_id

        :param client_id: client_id of client to be queried
        :param realm: client template from this realm
        :return: id of client (usually a UUID)
        """
        result = self.get_client_by_clientid(client_id, realm)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def get_client_secret(self, client_id, realm='master'):
        """ Obtain secret of client by client_id

        :param client_id: client_id of client to be queried
        :param realm: client template from this realm
        :return: secret of client 
        """
        secret_url=URL_CLIENT_SECRET.format(url=self.baseurl, realm=realm, id=client_id)
        try:
            return json.loads(to_native(open_url(secret_url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))

        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg='Could not obtain client %s for realm %s: %s'
                                          % (id, realm, str(e)))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain client %s for realm %s: %s'
                                      % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain client %s for realm %s: %s'
                                      % (id, realm, str(e)))

    def update_client(self, id, clientrep, realm="master"):
        """ Update an existing client
        :param id: id (not clientId) of client to be updated in Keycloak
        :param clientrep: corresponding (partial/full) client representation with updates
        :param realm: realm the client is in
        :return: HTTPResponse object on success
        """
        client_url = URL_CLIENT.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(client_url, method='PUT', headers=self.restheaders,
                            data=json.dumps(clientrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update client %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def create_client(self, clientrep, realm="master"):
        """ Create a client in keycloak
        :param clientrep: Client representation of client to be created. Must at least contain field clientId
        :param realm: realm for client to be created
        :return: HTTPResponse object on success
        """
        client_url = URL_CLIENTS.format(url=self.baseurl, realm=realm)

        try:
            return open_url(client_url, method='POST', headers=self.restheaders,
                            data=json.dumps(clientrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create client %s in realm %s: %s'
                                      % (clientrep['clientId'], realm, str(e)))

    def delete_client(self, id, realm="master"):
        """ Delete a client from Keycloak

        :param id: id (not clientId) of client to be deleted
        :param realm: realm of client to be deleted
        :return: HTTPResponse object on success
        """
        client_url = URL_CLIENT.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(client_url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete client %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_templates(self, realm='master'):
        """ Obtains client template representations for client templates in a realm

        :param realm: realm to be queried
        :return: list of dicts of client representations
        """
        url = URL_CLIENTTEMPLATES.format(url=self.baseurl, realm=realm)

        try:
            return json.loads(to_native(open_url(url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain list of client templates for realm %s: %s'
                                      % (realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain list of client templates for realm %s: %s'
                                      % (realm, str(e)))

    def get_client_template_by_id(self, id, realm='master'):
        """ Obtain client template representation by id

        :param id: id (not name) of client template to be queried
        :param realm: client template from this realm
        :return: dict of client template representation or None if none matching exist
        """
        url = URL_CLIENTTEMPLATE.format(url=self.baseurl, id=id, realm=realm)

        try:
            return json.loads(to_native(open_url(url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain client templates %s for realm %s: %s'
                                      % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain client template %s for realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_template_by_name(self, name, realm='master'):
        """ Obtain client template representation by name

        :param name: name of client template to be queried
        :param realm: client template from this realm
        :return: dict of client template representation or None if none matching exist
        """
        result = self.get_client_templates(realm)
        if isinstance(result, list):
            result = [x for x in result if x['name'] == name]
            if len(result) > 0:
                return result[0]
        return None

    def get_client_template_id(self, name, realm='master'):
        """ Obtain client template id by name

        :param name: name of client template to be queried
        :param realm: client template from this realm
        :return: client template id (usually a UUID)
        """
        result = self.get_client_template_by_name(name, realm)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def update_client_template(self, id, clienttrep, realm="master"):
        """ Update an existing client template
        :param id: id (not name) of client template to be updated in Keycloak
        :param clienttrep: corresponding (partial/full) client template representation with updates
        :param realm: realm the client template is in
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTTEMPLATE.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(url, method='PUT', headers=self.restheaders,
                            data=json.dumps(clienttrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update client template %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def create_client_template(self, clienttrep, realm="master"):
        """ Create a client in keycloak
        :param clienttrep: Client template representation of client template to be created. Must at least contain field name
        :param realm: realm for client template to be created in
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTTEMPLATES.format(url=self.baseurl, realm=realm)

        try:
            return open_url(url, method='POST', headers=self.restheaders,
                            data=json.dumps(clienttrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create client template %s in realm %s: %s'
                                      % (clienttrep['clientId'], realm, str(e)))

    def delete_client_template(self, id, realm="master"):
        """ Delete a client template from Keycloak

        :param id: id (not name) of client to be deleted
        :param realm: realm of client template to be deleted
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTTEMPLATE.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete client template %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def get_realm_by_name(self, realm):
        """ Get a top-level realm representation for a named realm

        :param name: name of the realm
        :return: Realm representation as a dict
        """
        url = URL_REALM.format(url=self.baseurl, realm=realm)

        try:
            return json.load(open_url(url, method='GET', headers=self.restheaders, validate_certs=self.validate_certs))
        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg='Could not obtain realm representation for realm %s: %s' % (realm, str(e)))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain realm representation for realm %s: %s' % (realm, to_native(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain realm representation for realm %s: %s' % (realm, to_native(e)))

    def create_realm(self, realmrep):
        """ Create a realm in keycloak
        :param realmrep: Realm representation for realm to be created
        :param realm: Realm name for realm to be created
        :return: HTTPResponse object on success
        """
        url = URL_REALMS.format(url=self.baseurl)

        try:
            return open_url(url, method='POST', headers=self.restheaders, data=json.dumps(realmrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create realm: %s' % to_native(e))

    def update_realm(self, realmrep, realm):
        """ Update an existing realm

        :param realmrep: realm representation with updates
        :param realm: realm to be updated
        :return: HTTPResponse object on success
        """
        url = URL_REALM.format(url=self.baseurl, realm=realm)

        try:
            return open_url(url, method='PUT', headers=self.restheaders, data=json.dumps(realmrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update realm %s: %s' % (realm, to_native(e)))

    def delete_realm(self, realm):
        """ Delete a realm from Keycloak

        :param realm: realm to be deleted
        :return: HTTPResponse object on success
        """
        url = URL_REALM.format(url=self.baseurl, realm=realm)

        try:
            return open_url(url, method='DELETE', headers=self.restheaders, validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete realm %s: %s' % (realm, to_native(e)))

    def get_client_scopes(self, realm='master'):
        """ Obtains client scope representations for client scopes in a realm

        :param realm: realm to be queried
        :return: list of dicts of client representations
        """
        url = URL_CLIENTSCOPES.format(url=self.baseurl, realm=realm)

        try:
            return json.loads(to_native(open_url(url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain list of client scopes for realm %s: %s'
                                      % (realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain list of client scopes for realm %s: %s'
                                      % (realm, str(e)))

    def get_client_scope_by_id(self, id, realm='master'):
        """ Obtain client scope representation by id

        :param id: id (not name) of client scope to be queried
        :param realm: client scope from this realm
        :return: dict of client scope representation or None if none matching exist
        """
        url = URL_CLIENTSCOPE.format(url=self.baseurl, id=id, realm=realm)

        try:
            return json.loads(to_native(open_url(url, method='GET', headers=self.restheaders,
                                                 validate_certs=self.validate_certs).read()))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain client scopes %s for realm %s: %s'
                                      % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain client scope %s for realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_scope_by_name(self, name, realm='master'):
        """ Obtain client scope representation by name

        :param name: name of client scope to be queried
        :param realm: client scope from this realm
        :return: dict of client scope representation or None if none matching exist
        """
        result = self.get_client_templates(realm)
        if isinstance(result, list):
            result = [x for x in result if x['name'] == name]
            if len(result) > 0:
                return result[0]
        return None

    def get_client_scope_id(self, name, realm='master'):
        """ Obtain client scope id by name

        :param name: name of client scope to be queried
        :param realm: client scope from this realm
        :return: client scope id (usually a UUID)
        """
        result = self.get_client_template_by_name(name, realm)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def update_client_scope(self, id, clientsrep, realm="master"):
        """ Update an existing client scope
        :param id: id (not name) of client scope to be updated in Keycloak
        :param clientsrep: corresponding (partial/full) client scope representation with updates
        :param realm: realm the client template is in
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTSCOPE.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(url, method='PUT', headers=self.restheaders,
                            data=json.dumps(clientsrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update client scope %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def create_client_scope(self, clientsrep, realm="master"):
        """ Create a client scope in keycloak
        :param clientsrep: Client scope representation of client scope to be created. Must at least contain field name
        :param realm: realm for client scope to be created in
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTSCOPES.format(url=self.baseurl, realm=realm)

        try:
            return open_url(url, method='POST', headers=self.restheaders,
                            data=json.dumps(clientsrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create client scope %s in realm %s: %s'
                                      % (clientsrep['clientId'], realm, str(e)))

    def delete_client_scope(self, id, realm="master"):
        """ Delete a client scope from Keycloak

        :param id: id (not name) of scope to be deleted
        :param realm: realm of client scope to be deleted
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTSCOPE.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete client scope %s in realm %s: %s'
                                      % (id, realm, str(e)))
