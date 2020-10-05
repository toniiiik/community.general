#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Eike Frost <ei@kefro.st>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: keycloak_default_scope

short_description: Allows administration of Keycloak client scopes via Keycloak API


description:
    - This module allows the administration of Keycloak client scopes via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_client_scopes_resource)

    - The Keycloak API does not always enforce for only sensible settings to be used -- you can set
      SAML-specific settings on an OpenID Connect client for instance and vice versa. Be careful.
      If you do not specify a setting, usually a sensible default is chosen.

options:
    state:
        description:
            - State of the client scope
            - On C(present), the client scope will be created (or updated if it exists already).
            - On C(absent), the client scope will be removed if it exists
        choices: ['present', 'absent']
        default: 'present'

    cid:
        description:
            - Id of client scope to be worked on. This is usually a UUID.

    realm:
        description:
            - Realm this client scope is found in.

    scope_names:
        description:
            -  A list of client-scope names.
        
extends_documentation_fragment:
- community.general.keycloak


author:
    - Eike Frost (@eikef)
'''

EXAMPLES = '''
- name: Create or update Keycloak client scope (minimal)
  local_action:
    module: keycloak_clienttemplate
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    name: this_is_a_test

- name: Delete Keycloak client scope
  local_action:
    module: keycloak_clienttemplate
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: absent
    name: test01

- name: Create or update Keycloak client scope (with a protocol mapper)
  local_action:
    module: keycloak_clienttemplate
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    name: this_is_a_test
    protocol_mappers:
      - config:
          access.token.claim: True
          claim.name: "family_name"
          id.token.claim: True
          jsonType.label: String
          user.attribute: lastName
          userinfo.token.claim: True
        consentRequired: True
        consentText: "${familyName}"
        name: family name
        protocol: openid-connect
        protocolMapper: oidc-usermodel-property-mapper
    full_scope_allowed: false
    id: bce6f5e9-d7d3-4955-817e-c5b7f8d65b3f
'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "client scope testclient has been updated"

proposed:
    description: client scope representation of proposed changes to client scope
    returned: always
    type: dict
    sample: {
      name: "test01"
    }
existing:
    description: client scope representation of existing client scope (sample is truncated)
    returned: always
    type: dict
    sample: {
        "description": "test01",
        "fullScopeAllowed": false,
        "id": "9c3712ab-decd-481e-954f-76da7b006e5f",
        "name": "test01",
        "protocol": "saml"
    }
end_state:
    description: client scope representation of client scope after module execution (sample is truncated)
    returned: always
    type: dict
    sample: {
        "description": "test01",
        "fullScopeAllowed": false,
        "id": "9c3712ab-decd-481e-954f-76da7b006e5f",
        "name": "test01",
        "protocol": "saml"
    }
'''

from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import KeycloakAPI, camel, \
    keycloak_argument_spec, get_token, KeycloakError
from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak_default_scope import KeycloakDefaultScopeAPI
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = keycloak_argument_spec()

    meta_args = dict(
        realm=dict(type='str', default='master'),
        state=dict(default='present', choices=['present', 'absent']),
        cid=dict(type='str'),
        scope_names=dict(type='list', elements='str'),
    )
    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['realm'],['scope_names']]))

    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    # Obtain access token, initialize API
    try:
        connection_header = get_token(
            base_url=module.params.get('auth_keycloak_url'),
            validate_certs=module.params.get('validate_certs'),
            auth_realm=module.params.get('auth_realm'),
            client_id=module.params.get('auth_client_id'),
            auth_username=module.params.get('auth_username'),
            auth_password=module.params.get('auth_password'),
            client_secret=module.params.get('auth_client_secret'),
        )
    except KeycloakError as e:
        module.fail_json(msg=str(e))
    kc = KeycloakDefaultScopeAPI(module, connection_header)
    kcscopes = KeycloakAPI(module, connection_header)

    realm = module.params.get('realm')
    scope_names = module.params.get('scope_names')
    cid = module.params.get('cid')

    all_scopes=kcscopes.get_client_scopes(realm)

    scopes_after=[item for item in all_scopes if item['name'] in scope_names]
    scopes_before=kc.get_default_scopes(realm=realm, cid=cid)

    changed = False if scopes_after == scopes_before else True

    if not changed:
        result['msg'] = "No changes required."
        if module._diff:
            result['diff'] = dict(before='', after='')
        module.exit_json(**result)

    result['changed']=True

    if module._diff:
        result['diff'] = dict(before=scopes_before, after=scopes_after)

    scopes_delete=[item for item in scopes_before if item not in scopes_after]
    scopes_add=[item for item in scopes_after if item not in scopes_before]    
    for s in scopes_delete:
        kc.delete_default_scope(realm=realm,cid=cid, scopeid=s.id)
    for s in scopes_add:
        kc.set_default_scope(realm=realm,cid=cid, scopeid=s.id)

    result['msg'] = "Default scopes sucessfully updated."

    module.exit_json(**result)


if __name__ == '__main__':
    main()
