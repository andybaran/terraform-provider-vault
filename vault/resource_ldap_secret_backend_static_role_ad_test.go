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

// AD integration tests require the following environment variables:
//
//	AD_URL      - LDAPS URL (e.g., ldaps://1.2.3.4)
//	AD_BIND_DN  - Admin bind DN (e.g., CN=Administrator,CN=Users,DC=mydomain,DC=local)
//	AD_BIND_PW  - Admin password
//	AD_USER_DN  - User container DN (e.g., CN=Users,DC=mydomain,DC=local)
//	AD_DOMAIN   - Domain suffix (e.g., DC=mydomain,DC=local)
//
// Test users must exist in AD: svc-rotate-a, svc-rotate-b, svc-single

// TestAccADSecretBackendStaticRole tests single-account static role against a real AD DC.
func TestAccADSecretBackendStaticRole(t *testing.T) {
	url, bindDN, bindPass, userDN, domain := testutil.GetTestADLDAPCreds(t)
	path := acctest.RandomWithPrefix("tf-test-ad-static-role")
	resourceType := "vault_ldap_secret_backend_static_role"
	resourceName := resourceType + ".role"
	username := "svc-single"
	dn := fmt.Sprintf("CN=svc-single,%s", userDN)
	rotationPeriod := "86400"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackendStaticRoleConfig(path, bindDN, bindPass, url, userDN, domain, username, dn, username, rotationPeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, rotationPeriod),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

// TestAccADSecretBackendStaticRole_DualAccount tests dual-account (blue/green)
// rotation against a real Active Directory domain controller.
func TestAccADSecretBackendStaticRole_DualAccount(t *testing.T) {
	url, bindDN, bindPass, userDN, domain := testutil.GetTestADLDAPCreds(t)
	path := acctest.RandomWithPrefix("tf-test-ad-dual-account")
	resourceType := "vault_ldap_secret_backend_static_role"
	resourceName := resourceType + ".role"
	username := "svc-rotate-a"
	dn := fmt.Sprintf("CN=svc-rotate-a,%s", userDN)
	usernameB := "svc-rotate-b"
	dnB := fmt.Sprintf("CN=svc-rotate-b,%s", userDN)
	rotationPeriod := "86400"
	gracePeriod := "3600"
	updatedRotationPeriod := "172800"
	updatedGracePeriod := "7200"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion121)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeLDAP, consts.FieldMount),
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackendStaticRoleConfig_DualAccount(path, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB, username, rotationPeriod, gracePeriod),
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
				Config: testADSecretBackendStaticRoleConfig_DualAccount(path, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB, username, updatedRotationPeriod, updatedGracePeriod),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, updatedRotationPeriod),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGracePeriod, updatedGracePeriod),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMount, consts.FieldRoleName),
		},
	})
}

// TestAccADDataSourceStaticRoleCredentials_DualAccount tests the credentials data
// source for a dual-account static role against a real AD domain controller.
func TestAccADDataSourceStaticRoleCredentials_DualAccount(t *testing.T) {
	url, bindDN, bindPass, userDN, domain := testutil.GetTestADLDAPCreds(t)
	path := acctest.RandomWithPrefix("tf-test-ad-dual-creds")
	username := "svc-rotate-a"
	dn := fmt.Sprintf("CN=svc-rotate-a,%s", userDN)
	usernameB := "svc-rotate-b"
	dnB := fmt.Sprintf("CN=svc-rotate-b,%s", userDN)
	dataName := "data.vault_ldap_static_credentials.creds"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion121)
		},
		Steps: []resource.TestStep{
			{
				Config: testADStaticRoleDualAccountDataSource(path, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldDualAccountMode, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldActiveAccount, "a"),
					resource.TestCheckResourceAttr(dataName, consts.FieldRotationState, "active"),
					resource.TestCheckResourceAttr(dataName, consts.FieldUsername, username),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldPassword),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldLastVaultRotation),
					resource.TestCheckResourceAttr(dataName, consts.FieldDN, dn),
					resource.TestCheckResourceAttr(dataName, consts.FieldRotationPeriod, "86400"),
					// Standby fields are empty during active state (only populated during grace_period)
					resource.TestCheckResourceAttr(dataName, consts.FieldStandbyUsername, ""),
					resource.TestCheckResourceAttr(dataName, consts.FieldStandbyDN, ""),
				),
			},
		},
	})
}

// testADSecretBackendStaticRoleConfig returns a TF config for a single-account
// static role against an AD backend with schema=ad and insecure_tls=true.
func testADSecretBackendStaticRoleConfig(mount, bindDN, bindPass, url, userDN, domain, username, dn, role, rotationPeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path         = "%[1]s"
  description  = "AD test backend"
  binddn       = "%[2]s"
  bindpass     = "%[3]s"
  url          = "%[4]s"
  userdn       = "%[5]s"
  insecure_tls = true
  schema       = "ad"
  userattr     = "sAMAccountName"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount           = vault_ldap_secret_backend.test.path
  username        = "%[7]s"
  dn              = "%[8]s"
  role_name       = "%[9]s"
  rotation_period = %[10]s
}
`, mount, bindDN, bindPass, url, userDN, domain, username, dn, role, rotationPeriod)
}

// testADSecretBackendStaticRoleConfig_DualAccount returns a TF config for a
// dual-account static role against an AD backend.
func testADSecretBackendStaticRoleConfig_DualAccount(mount, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB, role, rotationPeriod, gracePeriod string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path         = "%[1]s"
  description  = "AD test backend"
  binddn       = "%[2]s"
  bindpass     = "%[3]s"
  url          = "%[4]s"
  userdn       = "%[5]s"
  insecure_tls = true
  schema       = "ad"
  userattr     = "sAMAccountName"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount             = vault_ldap_secret_backend.test.path
  username          = "%[7]s"
  dn                = "%[8]s"
  username_b        = "%[9]s"
  dn_b              = "%[10]s"
  role_name         = "%[11]s"
  rotation_period   = %[12]s
  dual_account_mode = true
  grace_period      = %[13]s
}
`, mount, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB, role, rotationPeriod, gracePeriod)
}

// testADStaticRoleDualAccountDataSource returns a TF config for testing the
// credentials data source with a dual-account role against AD.
func testADStaticRoleDualAccountDataSource(path, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB string) string {
	return fmt.Sprintf(`
resource "vault_ldap_secret_backend" "test" {
  path         = "%[1]s"
  description  = "AD test backend"
  binddn       = "%[2]s"
  bindpass     = "%[3]s"
  url          = "%[4]s"
  userdn       = "%[5]s"
  insecure_tls = true
  schema       = "ad"
  userattr     = "sAMAccountName"
}

resource "vault_ldap_secret_backend_static_role" "role" {
  mount             = vault_ldap_secret_backend.test.path
  username          = "%[7]s"
  dn                = "%[8]s"
  username_b        = "%[9]s"
  dn_b              = "%[10]s"
  role_name         = "%[7]s"
  rotation_period   = 86400
  dual_account_mode = true
  grace_period      = 3600
}

data "vault_ldap_static_credentials" "creds" {
  mount     = vault_ldap_secret_backend.test.path
  role_name = vault_ldap_secret_backend_static_role.role.role_name
}
`, path, bindDN, bindPass, url, userDN, domain, username, dn, usernameB, dnB)
}
