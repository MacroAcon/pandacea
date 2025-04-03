package com.anastomo.core.models

data class PurposeTag(
    val purposeId: String,
    val displayName: String,
    val description: String,
    val category: String,
    val iconReference: String,
    val status: String,
    val createdAt: Long,
    val updatedAt: Long,
    val schemaVersion: String
) 