resource "azurerm_storage_account" "decoy" {
  name = "st${var.project_name}${random_string.suffix.result}"

  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version = "TLS1_2"

  tags = {
    project = var.project_name
    purpose = "decoy"
  }
}

resource "azurerm_storage_container" "decoy" {
  name               = "sensitive-data"
  storage_account_id = azurerm_storage_account.decoy.id

  container_access_type = "private"
}

resource "azurerm_storage_blob" "credentials" {
  name                   = "credentials.txt"
  storage_account_name   = azurerm_storage_account.decoy.name
  storage_container_name = azurerm_storage_container.decoy.name

  type         = "Block"
  content_type = "text/plain"

  source_content = <<EOT
Production Database Credentials
================================
Username: backup-admin
Password: DECOY_PASSWORD_NOT_REAL

Internal Use Only
EOT
}