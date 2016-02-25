======================================================
Porting documentation for thirdparty/nuage tests cases
======================================================

.. contents:: Table of contents
    :depth: 3

Introduction
============

This document clarifies changes on the merge of the original Nuage tempestr repo's toward the new repo based on the
tempest plugin architecture.

Original repo's:

- https://github.mv.usa.alcatel.com/OpenStack-QA/tempest
- https://github.mv.usa.alcatel.com/openstack/tempest

New repo:

- https://github.mv.usa.alcatel.com/pygash/nuage-tempest

See branch porting-tests

Execution results can be found at:

  http://172.31.222.216:8080/job/NuagePlugin-QA-Tempest-Kilo/Tempest_Test_Results/


Syncronisation with upstream
============================

tempest_lib
-----------
The tempest_lib repo has again been merged with tempest project. The package should no longer be installed and is
removed from requirements.txt

To avoid conflicts, you have to uninstall it from your current work (virtual) environment

OLD:

.. code-block:: python

    from tempest_lib import exceptions

NEW:

.. code-block:: python

    from tempest.lib import exceptions


VSD client is no longer managed by the tempest client manager
-------------------------------------------------------------

OLD:

.. code-block:: python


    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

        cls.nuage_vsd_client = cls.get_client_manager().nuage_vsd_client

NEW:

.. code-block:: python

    from nuagetempest.services import nuage_client

    [...]

    @classmethod
    def setup_clients(cls):
        super(NuagePatUnderlayBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()


All neutron resources have a dedicated client
---------------------------------------------

Change:

- *self.client.create_subnet* to *self.subnets_client.create_subnet*


Patch_update_router
-------------------
Overruled the upstream network_client/update_router method,
to allow update of Nuage extended attributes.

See nuagetempest/thirdparty/nuage/test_routers_nuage/#test_router_create_update_show_delete_with_backhaul_vnid_rt_rd
See nuagetempest/thirdparty/nuage/router/test_nuage_domain_tunnel_type.

Tempest.conf
------------

- removed deprecated attributes

OLD:

.. code-block:: ini

    [identity]
    allow_tenant_isolation = true

- move some attributes to new section

NEW:

.. code-block:: ini

    [auth]
    admin_tenant_name = admin
    admin_username = admin
    admin_role = admin
    admin_password = tigris
    admin_domain_name = regionOne
    use_dynamic_credentials = true

Differences dev/qa repo
=======================

External ID wrapper
-------------------

DEV-REPO:
   Assumes the External ID is decorated by the client.

.. code-block:: python

    nuage_vport = self.nuage_vsd_client.get_vport(n_constants.L2_DOMAIN,
                                                  nuage_subnet[0]['ID'],
                                                  filters='externalID',
                                                  filter_value=port_id)

QA-REPO:
    Method *get_vsd_external_id* is always used to ensure External ID is decorated with CMS_ID

.. code-block:: python

    port_ext_id = self.nuage_vsd_client.get_vsd_external_id(port_id)
    nuage_vport = self.nuage_vsd_client.get_vport(n_constants.L2_DOMAIN,
                                                  nuage_subnet[0]['ID'],
                                                  filters='externalID',
                                                  filter_value=port_ext_id)


PAT enabled tests
-----------------
For 2 tests, the check of PATenabled flag was

See nuagetempest/thirdparty/nuage/test_routers_nuage/#test_create_router_with_default_snat_value
See

Additional tests in OpenStack-QA/tempest
----------------------------------------
See nuagetempest/thirdparty/nuage/test_routers_nuage/#test_router_create_update_show_delete_with_backhaul_vnid_rt_rd
See nuagetempest/thirdparty/nuage/test_routers_nuage/#test_router_backhaul_vnid_rt_rd_negative

Other differences
-----------------
Most of the tests in /nuagetempest/thirdparty/nuage where available in both of the repo's,
but have been changed or extended without keeping both repo's in sync.

.. attention::
    Please check your tests in the new merge repo. In some cases, it was not clear which repo has the desired
    code.


Refactoring
===========

Use standard classmethods from BaseTestCase
-------------------------------------------
Tempest base test class has dedicated methods for

- setup_clients
- resource_setup
- resource_cleanup
- skip_checks

These methods shall be used, rather that doing all these actions in the *SetUp()* / *TearDown()* or *__init__*
See http://docs.openstack.org/developer/tempest/HACKING.html#test-fixtures-and-resources

OLD:

.. code-block:: python


    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

        cls.nuage_vsd_client = cls.get_client_manager().nuage_vsd_client

NEW:

.. code-block:: python

   @classmethod
    def setup_clients(cls):
        super(NuagePatUnderlayBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

    @classmethod
    def skip_checks(cls):
        super(NuagePatUnderlayBase, cls).skip_checks()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        if not CONF.service_available.neutron:
            msg = "Skipping all Neutron cli tests because it is not available"
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NuagePatUnderlayBase, cls).resource_setup()

        cls.ext_net_id = CONF.network.public_network_id


Remove duplicate code
---------------------
As a lot of helper methods are actually the test-class,
tests tend to either:

- inherit from multipe test classes
- duplicate the code

Better approach is to isolate domain specific code in dedicated classes.

To be defined...

Remove unappropriate inheritence
--------------------------------
Several classes superclass from an upstream base class, although not all behaviour is desired.
e.g. the baseNetworkClass always creates a set of resources for network, subnet, ports,...

Better to not inherit if the parent class behavior is not desired.

To be defined.

Dynamic credentials
-------------------
When the option is enabled in the tempest.conf, for each test class, credentials are created for:

- a tenant user (user with _member_ role)
- an admin user (user with "admin" role)

Both users are created for a different tenant !!!
As result, tests that require administration permissions for one resource, use the admin credentials for ALL resources.

For strict permission verification, we should have both a tenant_user (member role) and admin user (admin role)
for the SAME tenant.

To be defined.