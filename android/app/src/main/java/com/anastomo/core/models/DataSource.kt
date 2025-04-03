package com.anastomo.core.models

data class DataSource(
    val sourceId: String,
    val displayName: String,
    val description: String,
    val dataType: String,
    val defaultDataTier: Int,
    val collectionMethod: String,
    val sampleFormat: Map<String, Any>,
    val availabilityConditions: Map<String, Any>,
    val status: String,
    val schemaVersion: String
) 