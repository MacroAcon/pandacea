package com.anastomo.core.models

data class QueryResponse(
    val responseId: String,
    val queryId: String,
    val deviceId: String,
    val responsePayload: Map<String, Any>,
    val dataTierProvided: Int,
    val processingTimestamp: Long,
    val deliveryTimestamp: Long?,
    val responseQualityScore: Float,
    val schemaVersion: String
) 