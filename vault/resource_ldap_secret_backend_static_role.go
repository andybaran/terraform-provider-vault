// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func ldapSecretBackendStaticRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldMount: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeLDAP,
			Optional:     true,
			Description:  "The path where the LDAP secrets backend is mounted.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldRoleName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		consts.FieldUsername: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The username of the existing LDAP entry to manage password rotation for.",
			ForceNew:    true,
		},
		consts.FieldDN: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Distinguished name (DN) of the existing LDAP entry to manage password rotation for.",
		},
		consts.FieldRotationPeriod: {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "How often Vault should rotate the password of the user entry.",
		},
		consts.FieldSkipImportRotation: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Skip rotation of the password on import.",
		},
		consts.FieldDualAccountMode: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enable dual-account (blue/green) rotation mode. When enabled, two LDAP service accounts are managed per static role with blue/green rotation.",
			ForceNew:    true,
		},
		consts.FieldUsernameB: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The username of the second LDAP account (account B) when dual_account_mode is enabled.",
			ForceNew:    true,
		},
		consts.FieldDNB: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Distinguished name (DN) of the second LDAP account (account B) when dual_account_mode is enabled.",
		},
		consts.FieldGracePeriod: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Grace period duration in seconds where both account credentials are valid after rotation. Only used when dual_account_mode is enabled.",
		},
	}
	return &schema.Resource{
		CreateContext: createUpdateLDAPStaticRoleResource,
		UpdateContext: createUpdateLDAPStaticRoleResource,
		ReadContext:   provider.ReadContextWrapper(readLDAPStaticRoleResource),
		DeleteContext: deleteLDAPStaticRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var ldapSecretBackendStaticRoleFields = []string{
	consts.FieldUsername,
	consts.FieldDN,
	consts.FieldRotationPeriod,
	consts.FieldSkipImportRotation,
	consts.FieldDualAccountMode,
	consts.FieldUsernameB,
	consts.FieldDNB,
	consts.FieldGracePeriod,
}

func createUpdateLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	// Validate dual-account mode configuration.
	// Use d.Get() for booleans per SDKv2 best practice — d.GetOk() returns
	// (false, false) for booleans explicitly set to false, which is a known bug.
	if d.Get(consts.FieldDualAccountMode).(bool) {
		if _, ok := d.GetOk(consts.FieldUsernameB); !ok {
			return diag.FromErr(fmt.Errorf("username_b is required when dual_account_mode is enabled"))
		}
		if d.Get(consts.FieldGracePeriod).(int) <= 0 {
			return diag.FromErr(fmt.Errorf("grace_period is required and must be greater than 0 when dual_account_mode is enabled"))
		}
		if d.Get(consts.FieldSkipImportRotation).(bool) {
			return diag.FromErr(fmt.Errorf("skip_import_rotation cannot be used with dual_account_mode; dual-account initial setup requires import rotation"))
		}
	}

	mount := d.Get(consts.FieldMount).(string)
	role := d.Get(consts.FieldRoleName).(string)
	rolePath := fmt.Sprintf("%s/static-role/%s", mount, role)
	log.Printf("[DEBUG] Creating LDAP static role at %q", rolePath)
	data := map[string]interface{}{}
	for _, field := range ldapSecretBackendStaticRoleFields {
		// omit skip_import_rotation if vault version is less that 1.16 or if this is an update
		// (alternately, only include skip_import_rotation on new resources created on 1.16
		if field == consts.FieldSkipImportRotation && (!provider.IsAPISupported(meta, provider.VaultVersion116) || !d.IsNewResource()) {
			continue
		}
		// omit dual-account fields if vault version is less than 1.21
		if isDualAccountField(field) && !provider.IsAPISupported(meta, provider.VaultVersion121) {
			continue
		}
		if v, ok := d.GetOk(field); ok {
			data[field] = v
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, rolePath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", rolePath, err))
	}

	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readLDAPStaticRoleResource(ctx, d, meta)
}

func readLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	log.Printf("[DEBUG] Reading %q", rolePath)

	resp, err := client.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		return diag.FromErr(err)
	}

	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", rolePath)
		d.SetId("")
		return nil
	}
	for _, field := range ldapSecretBackendStaticRoleFields {
		if field == consts.FieldSkipImportRotation && !provider.IsAPISupported(meta, provider.VaultVersion116) {
			continue
		}
		// skip dual-account fields if vault version is less than 1.21
		if isDualAccountField(field) && !provider.IsAPISupported(meta, provider.VaultVersion121) {
			continue
		}
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
			}
		}
	}

	return nil
}

func deleteLDAPStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	_, err = client.Logical().DeleteWithContext(ctx, rolePath)
	if err != nil {
		if util.Is404(err) {
			d.SetId("")
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting static role %q: %w", rolePath, err))
	}

	return nil
}

// isDualAccountField returns true if the field is a dual-account specific field
// that requires Vault 1.21+ with the updated LDAP secrets plugin.
func isDualAccountField(field string) bool {
	switch field {
	case consts.FieldDualAccountMode, consts.FieldUsernameB, consts.FieldDNB, consts.FieldGracePeriod:
		return true
	}
	return false
}
