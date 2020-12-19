from casbin.enforcer import Enforcer
from casbin.util.rwlock import RWLockWrite, gen_synced_class

class SyncedEnforcer():

    def __init__(self, model=None, adapter=None, enable_log=False):
        self._e = Enforcer(model, adapter, enable_log)
        self._rwlock = RWLockWrite()
        self._rl = self._rwlock.gen_rlock()
        self._wl = self._rwlock.gen_wlock()

    def get_role_manager(self):
        """gets the current role manager."""
        return self._e.rm

    def enable_log(self, enable):
        """changes whether Casbin will log messages to the Logger."""
        return self._e.enable_log(enable)

    def clear_policy(self):
        """ clears all policy."""
        with self._wl:
            return self._e.clear_policy()

    def load_policy(self):
        """reloads the policy from file/database."""
        with self._wl:
            return self._e.load_policy()

    def load_filtered_policy(self, filter):
        """"reloads a filtered policy from file/database."""
        with self._wl:
            return self._e.load_filtered_policy(filter)

    def save_policy(self):
        with self._rl:
            return self._e.save_policy()

    def build_role_links(self):
        """manually rebuild the role inheritance relations."""
        with self._rl:
            return self._e.build_role_links()

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        with self._rl:
            return self._e.enforce(*rvals)

    def get_all_subjects(self):
        """gets the list of subjects that show up in the current policy."""
        with self._rl:
            return self._e.get_all_subjects()
    
    def get_all_named_subjects(self, ptype):
        """gets the list of subjects that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_named_subjects(ptype)

    def get_all_objects(self):
        """gets the list of objects that show up in the current policy."""
        with self._rl:
            return self._e.get_all_objects()

    def get_all_named_objects(self, ptype):
        """gets the list of objects that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_named_objects(ptype)

    def get_all_actions(self):
        """gets the list of actions that show up in the current policy."""
        with self._rl:
            return self._e.get_all_actions()

    def get_all_named_actions(self, ptype):
        """gets the list of actions that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_named_actions(ptype)

    def get_all_roles(self):
        """gets the list of roles that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_roles()

    def get_all_named_roles(self, ptype):
        """gets all the authorization rules in the policy."""
        with self._rl:
            return self._e.get_all_named_roles(ptype)

    def get_policy(self):
        """gets all the authorization rules in the policy."""
        with self._rl:
            return self._e.get_policy()

    def get_filtered_policy(self, field_index, *field_values):
        """gets all the authorization rules in the policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_policy(field_index, *field_values)

    def get_named_policy(self, ptype):
        """gets all the authorization rules in the named policy."""
        with self._rl:
            return self._e.get_named_policy(ptype)

    def get_filtered_named_policy(self, ptype, field_index, *field_values):
        """gets all the authorization rules in the named policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_named_policy(ptype, field_index, *field_values)

    def get_grouping_policy(self):
        """gets all the role inheritance rules in the policy."""
        with self._rl:
            return self._e.get_grouping_policy()

    def get_filtered_grouping_policy(self, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_grouping_policy(field_index, *field_values)

    def get_named_grouping_policy(self, ptype):
        """gets all the role inheritance rules in the policy."""
        with self._rl:
            return self._e.get_named_grouping_policy(ptype)

    def get_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_named_grouping_policy(ptype, field_index, *field_values)

    def has_policy(self, *params):
        """determines whether an authorization rule exists."""
        with self._rl:
            return self._e.has_policy(*params)

    def has_named_policy(self, ptype, *params):
        """determines whether a named authorization rule exists."""
        with self._rl:
            return self._e.has_named_policy(ptype, *params)

    def add_policy(self, *params):
        """adds an authorization rule to the current policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_policy(*params)

    def add_named_policy(self, ptype, *params):
        """adds an authorization rule to the current named policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_named_policy(ptype, *params)

    def remove_policy(self, *params):
        """removes an authorization rule from the current policy."""
        with self._wl:
            return self._e.remove_policy(*params)

    def remove_filtered_policy(self, field_index, *field_values):
        """removes an authorization rule from the current policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_policy(field_index, *field_values)

    def remove_named_policy(self, ptype, *params):
        """removes an authorization rule from the current named policy."""
        with self._wl:
            return self._e.remove_named_policy(ptype, *params)

    def remove_filtered_named_policy(self, ptype, field_index, *field_values):
        """removes an authorization rule from the current named policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_named_policy(ptype, field_index, *field_values)

    def has_grouping_policy(self, *params):
        """determines whether a role inheritance rule exists."""
        with self._rl:
            return self._e.has_grouping_policy(*params)

    def has_named_grouping_policy(self, ptype, *params):
        """determines whether a named role inheritance rule exists."""
        with self._rl:
            return self._e.has_named_grouping_policy(ptype, *params)

    def add_grouping_policy(self, *params):
        """adds a role inheritance rule to the current policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_grouping_policy(*params)

    def add_named_grouping_policy(self, ptype, *params):
        """adds a named role inheritance rule to the current policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_named_grouping_policy(ptype, *params)

    def remove_grouping_policy(self, *params):
        """removes a role inheritance rule from the current policy."""
        with self._wl:
            return self._e.remove_grouping_policy(*params)

    def remove_filtered_grouping_policy(self, field_index, *field_values):
        """removes a role inheritance rule from the current policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_grouping_policy(field_index, *field_values)

    def remove_named_grouping_policy(self, ptype, *params):
        """removes a role inheritance rule from the current named policy."""
        with self._wl:
            return self._e.remove_named_grouping_policy(ptype, *params)

    def remove_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """removes a role inheritance rule from the current named policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_named_grouping_policy(ptype, field_index, *field_values)

    def add_function(self, name, func):
        """adds a customized function."""
        with self._wl:
            return self._e.add_function(name, func)

    # enforcer.py

    def get_roles_for_user(self, name):
        """ gets the roles that a user has. """
        with self._rl:
            return self._e.get_roles_for_user(name)

    def get_users_for_role(self, name):
        """ gets the users that has a role. """
        with self._rl:
            return self._e.get_users_for_role(name)

    def has_role_for_user(self, name, role):
        """ determines whether a user has a role. """
        with self._rl:
            return self._e.has_role_for_user(name, role)

    def add_role_for_user(self, user, role):
        """
        adds a role for a user.
        Returns false if the user already has the role (aka not affected).
        """
        with self._wl:
            return self._e.add_role_for_user(user, role)

    def delete_role_for_user(self, user, role):
        """
        deletes a role for a user.
        Returns false if the user does not have the role (aka not affected).
        """
        with self._wl:
            return self._e.delete_role_for_user(user, role)

    def delete_roles_for_user(self, user):
        """
        deletes all roles for a user.
        Returns false if the user does not have any roles (aka not affected).
        """
        with self._wl:
            return self._e.delete_roles_for_user(user)

    def delete_user(self, user):
        """
        deletes a user.
        Returns false if the user does not exist (aka not affected).
        """
        with self._wl:
            return self._e.delete_user(user)

    def delete_role(self, role):
        """
        deletes a role.
        Returns false if the role does not exist (aka not affected).
        """
        with self._wl:
            return self._e.delete_role(role)

    def delete_permission(self, *permission):
        """
        deletes a permission.
        Returns false if the permission does not exist (aka not affected).
        """
        with self._wl:
            return self._e.delete_permission(*permission)

    def add_permission_for_user(self, user, *permission):
        """
        adds a permission for a user or role.
        Returns false if the user or role already has the permission (aka not affected).
        """
        with self._wl:
            return self._e.add_permission_for_user(user, *permission)

    def delete_permission_for_user(self, user, *permission):
        """
        deletes a permission for a user or role.
        Returns false if the user or role does not have the permission (aka not affected).
        """
        with self._wl:
            return self._e.delete_permission_for_user(user, *permission)

    def delete_permissions_for_user(self, user):
        """
        deletes permissions for a user or role.
        Returns false if the user or role does not have any permissions (aka not affected).
        """
        with self._wl:
            return self._e.delete_permissions_for_user(user)

    def get_permissions_for_user(self, user):
        """
        gets permissions for a user or role.
        """
        with self._rl:
            return self._e.get_permissions_for_user(user)

    def has_permission_for_user(self, user, *permission):
        """
        determines whether a user has a permission.
        """
        with self._rl:
            return self._e.has_permission_for_user(user, *permission)

    def get_implicit_roles_for_user(self, name, *domain):
        """
        gets implicit roles that a user has.
        Compared to get_roles_for_user(), this function retrieves indirect roles besides direct roles.
        For example:
        g, alice, role:admin
        g, role:admin, role:user

        get_roles_for_user("alice") can only get: ["role:admin"].
        But get_implicit_roles_for_user("alice") will get: ["role:admin", "role:user"].
        """
        with self._rl:
            return self._e.get_implicit_roles_for_user(name, *domain)

    def get_implicit_permissions_for_user(self, user, *domain):
        """
        gets implicit permissions for a user or role.
        Compared to get_permissions_for_user(), this function retrieves permissions for inherited roles.
        For example:
        p, admin, data1, read
        p, alice, data2, read
        g, alice, admin

        get_permissions_for_user("alice") can only get: [["alice", "data2", "read"]].
        But get_implicit_permissions_for_user("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
        """
        with self._rl:
            return self._e.get_implicit_permissions_for_user(user, *domain)

    def get_implicit_users_for_permission(self, *permission):
        """
        gets implicit users for a permission.
        For example:
        p, admin, data1, read
        p, bob, data1, read
        g, alice, admin

        get_implicit_users_for_permission("data1", "read") will get: ["alice", "bob"].
        Note: only users will be returned, roles (2nd arg in "g") will be excluded.
        """
        with self._rl:
            return self._e.get_implicit_users_for_permission(*permission)

    def get_roles_for_user_in_domain(self, name, domain):
        """gets the roles that a user has inside a domain."""
        with self._rl:
            return self._e.get_roles_for_user_in_domain(name, domain)

    def get_users_for_role_in_domain(self, name, domain):
        """gets the users that has a role inside a domain."""
        with self._rl:
            return self._e.get_users_for_role_in_domain(name, domain)

    def add_role_for_user_in_domain(self, user, role, domain):
        """adds a role for a user inside a domain."""
        """Returns false if the user already has the role (aka not affected)."""
        with self._wl:
            return self._e.add_role_for_user_in_domain(user, role, domain)

    def delete_roles_for_user_in_domain(self, user, role, domain):
        """deletes a role for a user inside a domain."""
        """Returns false if the user does not have any roles (aka not affected)."""
        with self._wl:
            return self._e.delete_roles_for_user_in_domain(user, role, domain)

    def get_permissions_for_user_in_domain(self, user, domain):
        """gets permissions for a user or role inside domain."""
        with self._rl:
            return self._e.get_permissions_for_user_in_domain(user, domain)