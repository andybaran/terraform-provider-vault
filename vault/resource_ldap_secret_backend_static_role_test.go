// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccLDAPSecretBackendStaticRole(t *testing.T) {
	var (
		path                  = acctest.RandomWithPrefix("tf-test-ldap-static-role")
		bindDN, bindPass, url = testutil.GetTestLDAPCreds(t)
		resourceType          = "vault_ldap_secret_backend_static_role"
		resourceName          = resourceType + ".role"
		username              = "alice"
		dn                    = "cn=alice,ou=users,dc=example,dc=org"
		rotationPeriod        = "60"
		updatedUsername       = "bob"
		updatedDN             = "cn=bob,ou=users,dc=example,dc=org"
		updatedRotationPeriod = "120"
	)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig(path, bindDN, bindPass, url, username, dn, username, rotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					return !testProvider.Meta().(*provider.ProviderMeta).IsAPISupported(provider.VaultVersion116), nil
				},
				Config: testLDAPSecretBackendStaticRoleConfig_withSkip(path, bindDN, bindPass, url, username, dn, username, rotationPeriod),
				Check:  resource.TestCheckResourceAttr(resourceName, consts.FieldSkipImportRotation, "true"),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig(path, bindDN, bindPass, url, updatedUsername, updatedDN, updatedUsername, updatedRotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, updatedDN),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, updatedUsername),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, updatedRotationPeriod),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

func testLDAPSecretBackendStaticRoleConfig(mount, bindDN, bindPass, url, username, dn, role, rotationPeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount            = vault_ldap_secret_backend.test.path
  username        = "%s"
  dn              = "%s"
  role_name       = "%s"
  rotation_period = %s
}
`, mount, bindDN, bindPass, url, username, dn, role, rotationPeriod)
}

func testLDAPSecretBackendStaticRoleConfig_withSkip(mount, bindDN, bindPass, url, username, dn, role, rotationPeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount            = vault_ldap_secret_backend.test.path
  username        = "%s"
  dn              = "%s"
  role_name       = "%s"
  rotation_period = %s
  skip_import_rotation = true
}
`, mount, bindDN, bindPass, url, username, dn, role, rotationPeriod)
}

func TestAccLDAPSecretBackendStaticRole_DualAccount(t *testing.T) {
	var (
		path                   = acctest.RandomWithPrefix("tf-test-ldap-dual-account")
		bindDN, bindPass, url  = testutil.GetTestLDAPCreds(t)
		resourceType           = "vault_ldap_secret_backend_static_role"
		resourceName           = resourceType + ".role"
		username               = "alice"
		dn                     = "cn=alice,ou=users,dc=example,dc=org"
		usernameB              = "alice-b"
		dnB                    = "cn=alice-b,ou=users,dc=example,dc=org"
		rotationPeriod         = "86400"
		gracePeriod            = "3600"
		updatedGracePeriod     = "7200"
		updatedRotationPeriod  = "172800"
	)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testLDAPSecretBackendStaticRoleConfig_DualAccount(path, bindDN, bindPass, url, username, dn, usernameB, dnB, username, rotationPeriod, gracePeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDualAccountMode, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsernameB, usernameB),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDNB, dnB),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGracePeriod, gracePeriod),
				),
			},
			{
				Config: testLDAPSecretBackendStaticRoleConfig_DualAccount(path, bindDN, bindPass, url, username, dn, usernameB, dnB, username, updatedRotationPeriod, updatedGracePeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, updatedRotationPeriod),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGracePeriod, updatedGracePeriod),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

func testLDAPSecretBackendStaticRoleConfig_DualAccount(mount, bindDN, bindPass, url, username, dn, usernameB, dnB, role, rotationPeriod, gracePeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount             = vault_ldap_secret_backend.test.path
  username          = "%s"
  dn                = "%s"
  username_b        = "%s"
  dn_b              = "%s"
  role_name         = "%s"
  rotation_period   = %s
  dual_account_mode = true
  grace_period      = %s
}
`, mount, bindDN, bindPass, url, username, dn, usernameB, dnB, role, rotationPeriod, gracePeriod)
}

