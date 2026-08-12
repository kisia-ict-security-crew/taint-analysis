# 모든 Honeytoken 관련 로그를 모아두는 중앙 로그 저장소

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.project_name}-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  sku               = "PerGB2018"
  retention_in_days = 30

  tags = {
    project     = var.project_name
    environment = "lab"
    purpose     = "honeytoken-monitoring"
  }
}


# Key Vault 로그 수집
# prod-api-key 조회 / 수정 / 삭제 등의 이벤트 수집

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name = "diag-keyvault"

  # 감시 대상
  target_resource_id = azurerm_key_vault.decoy.id

  # 로그를 보낼 곳
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}


# Blob Storage 로그 수집
# 현재 구성된 임시 데이터: credentials.txt
# Blob이 읽히거나 수정/삭제되는 이벤트 수집

resource "azurerm_monitor_diagnostic_setting" "blob" {
  name = "diag-blob"

  target_resource_id = "${azurerm_storage_account.decoy.id}/blobServices/default"

  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
}


# Honey Service Principal 인증 시도 수집

resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  name = "diag-honey-identity"

  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "ServicePrincipalSignInLogs"
  }

  # Service Principal 생성/수정 등의 관리 행위도 함께 수집
  enabled_log {
    category = "AuditLogs"
  }
}