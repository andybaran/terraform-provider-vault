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

func TestAccDataSourceLDAPStaticRoleCredentials(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap-static-role-credentials")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	dn := "cn=alice,ou=users,dc=example,dc=org"
	username := "alice"
	dataName := "data.vault_ldap_static_credentials.creds"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		Steps: []resource.TestStep{
			{
				Config: testLDAPStaticRoleDataSource(backend, bindDN, bindPass, url, username, dn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(dataName, consts.FieldRotationPeriod, "60"),
					resource.TestCheckResourceAttr(dataName, consts.FieldLastPassword, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldDN, dn),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldPassword),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldTTL),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastVaultRotation),
				),
			},
		},
	})
}

func testLDAPStaticRoleDataSource(path, bindDN, bindPass, url, username, dn string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%s"
  description               = "test description"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount = vault_ldap_secret_backend.test.path
  username = "%s"
  dn = "%s"
  role_name = "%s"
  rotation_period = 60
}

data "vault_ldap_static_credentials" "creds" {
  mount = vault_ldap_secret_backend.test.path
  role_name  = vault_ldap_secret_backend_static_role.role.role_name
}
`, path, bindDN, bindPass, url, username, dn, username)
}

func TestAccDataSourceLDAPStaticRoleCredentials_DualAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap-dual-creds")
	bindDN, bindPass, url := testutil.GetTestLDAPCreds(t)
	dn := "cn=alice,ou=users,dc=example,dc=org"
	dnB := "cn=alice-b,ou=users,dc=example,dc=org"
	username := "alice"
	usernameB := "alice-b"
	dataName := "data.vault_ldap_static_credentials.creds"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion121)
		},
		Steps: []resource.TestStep{
			{
				Config: testLDAPStaticRoleDualAccountDataSource(backend, bindDN, bindPass, url, username, dn, usernameB, dnB),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldDualAccountMode, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldActiveAccount, "a"),
					resource.TestCheckResourceAttr(dataName, consts.FieldRotationState, "active"),
					resource.TestCheckResourceAttr(dataName, consts.FieldUsername, username),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldPassword),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastVaultRotation),
					resource.TestCheckResourceAttr(dataName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(dataName, consts.FieldRotationPeriod, "86400"),
				),
			},
		},
	})
}

func testLDAPStaticRoleDualAccountDataSource(path, bindDN, bindPass, url, username, dn, usernameB, dnB string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path                      = "%%[1]s"
  description               = "test description"
  binddn                    = "%%[2]s"
  bindpass                  = "%%[3]s"
  url                       = "%%[4]s"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount             = vault_ldap_secret_backend.test.path
  username          = "%%[5]s"
  dn                = "%%[6]s"
  username_b        = "%%[7]s"
  dn_b              = "%%[8]s"
  role_name         = "%%[5]s"
  rotation_period   = 86400
  dual_account_mode = true
  grace_period      = 3600
}

data "vault_ldap_static_credentials" "creds" {
  mount     = vault_ldap_secret_backend.test.path
  role_name = vault_ldap_secret_backend_static_role.role.role_name
}
`, path, bindDN, bindPass, url, username, dn, usernameB, dnB)
}
