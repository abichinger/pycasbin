from casbin.enforcer import Enforcer
from casbin.util.rwlock import RWLockWrite, gen_synced_class

SEnforcer = gen_synced_class('SEnforcer', (Enforcer,), 
    wl_functions=[
        Enforcer.load_policy
    ], 
    rl_functions=[
        Enforcer.save_policy
    ],
)

class SyncedEnforcer(Enforcer):

    def __init__(self, model=None, adapter=None, enable_log=False):
        super(SyncedEnforcer, self).__init__(model, adapter, enable_log)
        self._rwlock = RWLockWrite()
        self._rl = self._rwlock.gen_rlock()
        self._wl = self._rwlock.gen_wlock()

    def clear_policy(self):
        with self._wl:
            return super().clear_policy()

    def load_policy(self):
        with self._wl:
            return super().load_policy()

    def load_filtered_policy(self, filter):
        with self._wl:
            return super().load_filtered_policy(filter)

    def save_policy(self):
        with self._rl:
            return super().save_policy()

    def build_role_links(self):
        with self._rl:
            return super().build_role_links()

    def enforce(self, *rvals):
        with self._rl:
            return super().enforce(*rvals)

    def get_all_subjects(self):
        """gets the list of subjects that show up in the current policy."""
        with self._rl:
            return super().get_all_subjects()
    
    def get_all_named_subjects(self, ptype):
        """gets the list of subjects that show up in the current named policy."""
        with self._rl:
            return super().get_all_named_subjects(ptype)

    def get_all_objects(self):
        """gets the list of objects that show up in the current policy."""
        with self._rl:
            return super().get_all_objects()

    def get_all_named_objects(self, ptype):
        """gets the list of objects that show up in the current named policy."""
        with self._rl:
            return super().get_all_named_objects(ptype)

    def get_all_actions(self):
        """gets the list of actions that show up in the current policy."""
        with self._rl:
            return super().get_all_actions()

    def get_all_named_actions(self, ptype):
        """gets the list of actions that show up in the current named policy."""
        with self._rl:
            return super().get_all_named_actions(ptype)

    def get_all_roles(self):
        """gets the list of roles that show up in the current named policy."""
        with self._rl:
            return super().get_all_roles()

    def get_all_named_roles(self, ptype):
        """gets all the authorization rules in the policy."""
        with self._rl:
            return super().get_all_named_roles(ptype)

    def get_policy(self):
        """gets all the authorization rules in the policy."""
        with self._rl:
            return super().get_policy()

    def get_filtered_policy(self, field_index, *field_values):
        """gets all the authorization rules in the policy, field filters can be specified."""
        with self._rl:
            return super().get_filtered_policy(field_index, *field_values)

    def get_named_policy(self, ptype):
        """gets all the authorization rules in the named policy."""
        with self._rl:
            return super().get_named_policy(ptype)

    def get_filtered_named_policy(self, ptype, field_index, *field_values):
        """gets all the authorization rules in the named policy, field filters can be specified."""
        with self._rl:
            return super().get_filtered_named_policy(ptype, field_index, *field_values)

    def get_grouping_policy(self):
        """gets all the role inheritance rules in the policy."""
        with self._rl:
            return super().get_grouping_policy()

    def get_filtered_grouping_policy(self, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        with self._rl:
            return super().get_filtered_grouping_policy(field_index, *field_values)

    def get_named_grouping_policy(self, ptype):
        """gets all the role inheritance rules in the policy."""
        with self._rl:
            return super().get_named_grouping_policy(ptype)

    def get_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        with self._rl:
            return super().get_filtered_named_grouping_policy(ptype, field_index, *field_values)

    def has_policy(self, *params):
        """determines whether an authorization rule exists."""
        with self._rl:
            return super().has_policy(*params)

    def has_named_policy(self, ptype, *params):
        """determines whether a named authorization rule exists."""
        with self._rl:
            return super().has_named_policy(ptype, *params)

    def add_policy(self, *params):
        """adds an authorization rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return super().add_policy(*params)

    def add_named_policy(self, ptype, *params):
        """adds an authorization rule to the current named policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return super().add_named_policy(ptype, *params)

    def remove_policy(self, *params):
        """removes an authorization rule from the current policy."""
        with self._wl:
            return super().remove_policy(*params)

    def remove_filtered_policy(self, field_index, *field_values):
        """removes an authorization rule from the current policy, field filters can be specified."""
        with self._wl:
            return super().remove_filtered_policy(field_index, *field_values)

    def remove_named_policy(self, ptype, *params):
        """removes an authorization rule from the current named policy."""
        with self._wl:
            return super().remove_named_policy(ptype, *params)

    def remove_filtered_named_policy(self, ptype, field_index, *field_values):
        """removes an authorization rule from the current named policy, field filters can be specified."""
        with self._wl:
            return super().remove_filtered_named_policy(ptype, field_index, *field_values)

    def has_grouping_policy(self, *params):
        """determines whether a role inheritance rule exists."""
        with self._rl:
            return super().has_grouping_policy(*params)

    def has_named_grouping_policy(self, ptype, *params):
        """determines whether a named role inheritance rule exists."""
        with self._rl:
            return super().has_named_grouping_policy(ptype, *params)

    def add_grouping_policy(self, *params):
        """adds a role inheritance rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return super().add_grouping_policy(*params)

    def add_named_grouping_policy(self, ptype, *params):
        """adds a named role inheritance rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return super().add_named_grouping_policy(ptype, *params)

    def remove_grouping_policy(self, *params):
        """removes a role inheritance rule from the current policy."""
        with self._wl:
            return super().remove_grouping_policy(*params)

    def remove_filtered_grouping_policy(self, field_index, *field_values):
        """removes a role inheritance rule from the current policy, field filters can be specified."""
        with self._wl:
            return super().remove_filtered_grouping_policy(field_index, *field_values)

    def remove_named_grouping_policy(self, ptype, *params):
        """removes a role inheritance rule from the current named policy."""
        with self._wl:
            return super().remove_named_grouping_policy(ptype, *params)

    def remove_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """removes a role inheritance rule from the current named policy, field filters can be specified."""
        with self._wl:
            return super().remove_filtered_named_grouping_policy(ptype, field_index, *field_values)

    def add_function(self, name, func):
        """adds a customized function."""
        with self._wl:
            return super().add_function(name, func)

    # def add_policies(self, rules):
    #     pass

    # def add_named_policies(self, ptype, rules):
    #     pass

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
        with self._wl:
            return super().get_implicit_roles_for_user(name, *domain)

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
        with self._wl:
            return super().get_implicit_permissions_for_user(user, *domain)

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
        with self._wl:
            return super().get_implicit_users_for_permission(*permission)