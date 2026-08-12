resource "azurerm_key_vault" "decoy" {
  name = "kv-${var.project_name}-${random_string.suffix.result}"

  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name = "standard"

  rbac_authorization_enabled = true

  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = {
    project = var.project_name
    purpose = "decoy"
  }
}

resource "azurerm_role_assignment" "terraform_kv_secret_officer" {
  scope                = azurerm_key_vault.decoy.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_secret" "honey" {
  name         = "prod-api-key"
  value        = var.honey_secret_value
  key_vault_id = azurerm_key_vault.decoy.id

  depends_on = [
    azurerm_role_assignment.terraform_kv_secret_officer
  ]
}