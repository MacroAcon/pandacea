package com.anastomo.core.models

data class ConsentHistory(
    val historyId: String,
    val consentId: String,
    val userId: String,
    val status: String,
    val timestamp: Long,
    val versionHash: String,
    val changeReason: String,
    val changeSource: String,
    val previousVersionHash: String?,
    val schemaVersion: String
) 