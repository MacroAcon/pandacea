package com.anastomo.core.models

data class Consent(
    val consentId: String,
    val dataSourceId: String,
    val purposeTag: String,
    val allowedDataTier: Int,
    val allowedPartnerTier: String,
    val status: String,
    val granularityDetails: Map<String, Any>,
    val grantedAt: Long,
    val expiresAt: Long?,
    val revokedAt: Long?,
    val lastUpdatedAt: Long,
    val createdBy: String,
    val schemaVersion: String
) 