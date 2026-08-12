data "azurerm_client_config" "current" {}

resource "azuread_application" "honey" {
  display_name = "sp-${var.project_name}-honey-${random_string.suffix.result}"
}

resource "azuread_service_principal" "honey" {
  client_id = azuread_application.honey.client_id
}

resource "azuread_application_password" "honey" {
  application_id = azuread_application.honey.id
  display_name   = "honey-client-secret"
}

resource "azurerm_role_assignment" "honey_blob_reader" {
  scope                = azurerm_storage_account.decoy.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azuread_service_principal.honey.object_id
}

resource "azurerm_role_assignment" "honey_kv_reader" {
  scope                = azurerm_key_vault.decoy.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azuread_service_principal.honey.object_id
}