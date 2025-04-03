package com.anastomo.core.models

data class Query(
    val queryId: String,
    val dataSourceId: String,
    val purposeTag: String,
    val requestedDataTier: Int,
    val partnerTier: String,
    val queryPayload: Map<String, Any>,
    val targetCriteria: Map<String, Any>?,
    val status: String,
    val submittedAt: Long,
    val completedAt: Long?,
    val errorDetails: String?,
    val responseFormat: String,
    val estimatedDeviceReach: Int,
    val estimatedCost: Double,
    val createdBy: String,
    val schemaVersion: String
) 