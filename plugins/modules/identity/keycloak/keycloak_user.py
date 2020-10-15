#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Adam Goossens <adam.goossens@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: keycloak_user

short_description: Allows administration of Keycloak users via Keycloak API

description:
    - This module allows you to add, remove or modify Keycloak users via the Keycloak REST API.
      It requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/8.0/rest-api/index.html).

    - Attributes are multi-valued in the Keycloak API. All attributes are lists of individual values and will
      be returned that way by this module. You may pass single values for attributes when calling the module,
      and this will be translated into a list suitable for the API.

    - When updating a user, where possible provide the user ID to the module. This removes a lookup
      to the API to translate the name into the user ID.


options:
    state:
        description:
            - State of the user.
            - On C(present), the user will be created if it does not yet exist, or updated with the parameters you provide.
            - On C(absent), the user will be removed if it exists.
        default: 'present'
        type: str
        choices:
            - present
            - absent
    
    last_name:
        type: str
        description:
            - Last of the user.
        alias: lastName

    first_name:
        type: str
        description:
            - First name of the user
        alias: firstName
    
    username:
        type: str
        description:
            - Username of the user.
            - This parameter is required only when creating or updating the user.

    realm:
        type: str
        description:
            - They Keycloak realm under which this user resides.
        default: 'master'

    id:
        type: str
        description:
            - The unique identifier for this user.
            - This parameter is not required for updating or deleting a user but
              providing it will reduce the number of API calls required.

    credentials:
        description:
          - Define one or more credentials for the user.
        suboptions:
            id:
                description:
                    - The unique identifier for the credential representation.
            value:
                description:
                    - Credential value.

            temporary:
                type: bool
                description:
                    - Specifies wheather credential is temporary.

            type:
                description:
                    - Specifies the type of the credential.
                default: 'password'
    groups:
      description:
        - List of groups user belongs to.

    attributes:
        type: dict
        description:
            - A dict of key/value pairs to set as custom attributes for the user.
            - Values may be single values (e.g. a string) or a list of strings.

extends_documentation_fragment:
- community.general.keycloak


author:
    - Anton Lysina (@toniiiik)
'''

EXAMPLES = '''
- name: Create a Keycloak user
  community.general.keycloak_user:
    username: my-user
    realm: MyCustomRealm
    state: present
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
  delegate_to: localhost

- name: Delete a Keycloak user
  community.general.keycloak_user:
    id: '9d59aa76-2755-48c6-b1af-beb70a82c3cd'
    state: absent
    realm: MyCustomRealm
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
  delegate_to: localhost

- name: Delete a Keycloak user based on name
  community.general.keycloak_user:
    name: my-user
    state: absent
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
  delegate_to: localhost

- name: Update the name of a Keycloak user
  community.general.keycloak_user:
    id: '9d59aa76-2755-48c6-b1af-beb70a82c3cd'
    first_name: My
    last_name: User
    state: present
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
  delegate_to: localhost

- name: Create a Keycloak user with some custom attributes
  community.general.keycloak_user:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    username: my-user
    attributes:
        attrib1: value1
        attrib2: value2
        attrib3:
            - with
            - numerous
            - individual
            - list
            - items
  delegate_to: localhost
'''

RETURN = '''
user:
  description: User representation of the user after module execution (sample is truncated).
  returned: always
  type: complex
  contains:
    id:
      description: GUID that identifies the user
      type: str
      returned: always
      sample: 23f38145-3195-462c-97e7-97041ccea73e
    name:
      description: Name of the user
      type: str
      returned: always
      sample: grp-test-123
    attributes:
      description: Attributes applied to this user
      type: dict
      returned: always
      sample:
        attr1: ["val1", "val2", "val3"]
    path:
      description: URI path to the user
      type: str
      returned: always
      sample: /grp-test-123
    realmRoles:
      description: An array of the realm-level roles granted to this user
      type: list
      returned: always
      sample: []
    groups:
      description: A list of groups that user belongs to.
      type: list
      returned: always
    clientRoles:
      description: A list of client-level roles granted to this user
      type: list
      returned: always
      sample: []
    access:
      description: A dict describing the accesses you have to this user based on the credentials used.
      type: dict
      returned: always
      sample:
        manage: true
        manageMembership: true
        view: true
'''

from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import camel, \
    keycloak_argument_spec, get_token, KeycloakError
from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak_user import KeycloakUserAPI
from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak_group import KeycloakGroupAPI
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Module execution

    :return:
    """
    credential_spec = dict(
        value=dict(type='str'),
        temporary=dict(type='bool'),
        id=dict(type='str'),
        type=dict(type='str', default='password'),
    )

    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(default='master'),
        id=dict(type='str'),
        username=dict(type='str'),
        enabled=dict(type='bool', default=True),
        credentials=dict(type='list', elements='dict', options=credential_spec),
        groups=dict(type='list', elements='str'),
        attributes=dict(type='dict')
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['id', 'username']]))

    result = dict(changed=False, msg='', diff=[], user='')

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
    kc = KeycloakUserAPI(module, connection_header)
    kcgroup = KeycloakGroupAPI(module, connection_header)

    realm = module.params.get('realm')
    state = module.params.get('state')
    uid = module.params.get('id')
    name = module.params.get('username')
    attributes = module.params.get('attributes')

    before_user = None         # current state of the user, for merging.

    # does the user already exist?
    if uid is None:
        before_user = kc.get_user_by_username(username=name, realm=realm)
    else:
        before_user = kc.get_user_by_id(uid, realm=realm)

    before_user = {} if before_user is None else before_user

    # attributes in Keycloak have their values returned as lists
    # via the API. attributes is a dict, so we'll transparently convert
    # the values to lists.
    if attributes is not None:
        for key, val in module.params['attributes'].items():
            module.params['attributes'][key] = [val] if not isinstance(val, list) else val

    user_params = [x for x in module.params
                    if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm'] and
                    module.params.get(x) is not None]

    # build a changeset
    changeset = dict()
    for param in user_params:
        new_param_value = module.params.get(param)
        old_value = before_user[param] if param in before_user else None
        if new_param_value != old_value:
            changeset[camel(param)] = new_param_value

    # prepare the new user
    updated_user = before_user.copy()
    updated_user.update(changeset)

    # if before_user is none, the user doesn't exist.
    if before_user == {}:
        if state == 'absent':
            # nothing to do.
            if module._diff:
                result['diff'] = dict(before='', after='')
            result['msg'] = 'User does not exist; doing nothing.'
            result['user'] = dict()
            module.exit_json(**result)

        # for 'present', create a new user.
        result['changed'] = True
        if name is None:
            module.fail_json(msg='name must be specified when creating a new user')

        if module._diff:
            result['diff'] = dict(before='', after=updated_user)

        if module.check_mode:
            module.exit_json(**result)

        # do it for real!
        kc.create_user(updated_user, realm=realm)
        after_user = kc.get_user_by_username(name, realm)

        result['user'] = after_user
        result['msg'] = 'User {username} has been created with ID {id}'.format(username=after_user['username'],
                                                                            id=after_user['id'])

    else:
        if state == 'present':
            # when user exists and state is present keycloak api ignore credentials, groups and other entities.
            # These entities must by updated by their concrete api
            # no changes

            members_of_update_paths = updated_user.pop('groups', None)
            all_groups=kcgroup.get_groups(realm, flatten=True)
            members_of_update = [item for item in all_groups if item['path'] in members_of_update_paths]
            group_missing = True if len(members_of_update_paths) != len(members_of_update) else False
            
            credentials_update = updated_user.pop('credentials', None)
            member_of = kc.get_user_groups(updated_user['id'], realm=realm)

            members_change = False if member_of == members_of_update else True
            user_change = False if updated_user == before_user else True
            if user_change == False and members_change == False:
                result['changed'] = False
                result['user'] = updated_user
                if group_missing:
                  result['msg'] = "No changes required to user {name}. Some group is missing please check the keycloak groups".format(name=before_user['username'])
                else:
                  result['msg'] = "No changes required to user {name}.".format(name=before_user['username'])
                module.exit_json(**result)

            # update the existing user
            result['changed'] = True

            if module._diff:
                if user_change:
                  result['diff'].append(dict(before=before_user, after=updated_user)) 
                if members_change:
                  result['diff'].append(dict(before=member_of, after=members_of_update)) 

            if module.check_mode:
                module.exit_json(**result)

            # do the update
            if user_change:
              kc.update_user(updated_user, realm=realm)
              # after_user = kc.get_user_by_id(updated_user['id'], realm=realm)
            
            if members_change:
              member_of_delete = [item for item in member_of if item not in members_of_update]
              member_of_add=[item for item in members_of_update if item not in member_of]
              for m in member_of_delete:
                kc.delete_user_from_group(updated_user['id'], groupid=m['id'], realm=realm)
              for m in member_of_add:
                kc.add_user_to_group(updated_user['id'], groupid=m['id'],realm=realm)

            result['user'] = updated_user
            if group_missing:
              result['msg'] = "User {id} has been updated but some of the group is missing".format(id=updated_user['id'])
            else:
              result['msg'] = "User {id} has been updated".format(id=updated_user['id'])

            module.exit_json(**result)

        elif state == 'absent':
            result['user'] = dict()

            if module._diff:
                result['diff'] = dict(before=before_user, after='')

            if module.check_mode:
                module.exit_json(**result)

            # delete for real
            uid = before_user['id']
            kc.delete_user(userid=uid, realm=realm)

            result['changed'] = True
            result['msg'] = "User {name} has been deleted".format(name=before_user['username'])

            module.exit_json(**result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
