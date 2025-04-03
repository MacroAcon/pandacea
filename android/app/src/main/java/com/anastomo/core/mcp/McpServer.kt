package com.anastomo.core.mcp

import android.content.Context
import com.anastomo.core.models.Query
import com.anastomo.core.models.QueryResponse
import com.anastomo.core.query.QueryEvaluator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.TimeUnit

class McpServer private constructor(context: Context) {
    private val queryEvaluator = QueryEvaluator.getInstance(context)
    private val coroutineScope = CoroutineScope(Dispatchers.IO)
    private var webSocket: WebSocket? = null
    private val client = OkHttpClient.Builder()
        .readTimeout(3, TimeUnit.SECONDS)
        .build()

    companion object {
        @Volatile
        private var instance: McpServer? = null

        fun getInstance(context: Context): McpServer {
            return instance ?: synchronized(this) {
                instance ?: McpServer(context.applicationContext).also { instance = it }
            }
        }
    }

    fun connect(serverUrl: String) {
        val request = Request.Builder()
            .url(serverUrl)
            .build()

        val listener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                this@McpServer.webSocket = webSocket
                // Send device registration message
                sendDeviceRegistration()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                // Handle connection failure
                reconnect()
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
            }
        }

        client.newWebSocket(request, listener)
    }

    private fun sendDeviceRegistration() {
        val message = JSONObject().apply {
            put("type", "device_registration")
            put("device_id", "current_device_id") // TODO: Get actual device ID
            put("device_model", android.os.Build.MODEL)
            put("os_version", android.os.Build.VERSION.RELEASE)
            put("anastomo_app_version", "1.0.0") // TODO: Get actual version
            put("status", "online")
            put("device_trust_level", "high")
            put("last_seen_at", System.currentTimeMillis())
            put("registered_at", System.currentTimeMillis())
            put("consent_summary", JSONObject()) // TODO: Get actual consent summary
            put("performance_metrics", JSONObject()) // TODO: Get actual metrics
            put("created_by", "device")
            put("schema_version", "1.0")
        }.toString()

        webSocket?.send(message)
    }

    private fun handleMessage(text: String) {
        try {
            val message = JSONObject(text)
            when (message.getString("type")) {
                "query" -> handleQuery(message)
                "heartbeat" -> handleHeartbeat()
                else -> {
                    // Unknown message type
                    sendError("unknown_message_type", "Unknown message type received")
                }
            }
        } catch (e: Exception) {
            sendError("invalid_message", "Failed to parse message: ${e.message}")
        }
    }

    private fun handleQuery(message: JSONObject) {
        coroutineScope.launch {
            try {
                val query = Query(
                    queryId = message.getString("query_id"),
                    dataSourceId = message.getString("data_source_id"),
                    purposeTag = message.getString("purpose_tag"),
                    requestedDataTier = message.getInt("requested_data_tier"),
                    partnerTier = message.getString("partner_tier"),
                    queryPayload = message.getJSONObject("query_payload").toMap(),
                    targetCriteria = message.optJSONObject("target_criteria")?.toMap(),
                    status = "processing",
                    submittedAt = message.getLong("submitted_at"),
                    completedAt = null,
                    errorDetails = null,
                    responseFormat = message.getString("response_format"),
                    estimatedDeviceReach = message.getInt("estimated_device_reach"),
                    estimatedCost = message.getDouble("estimated_cost"),
                    createdBy = message.getString("created_by"),
                    schemaVersion = message.getString("schema_version")
                )

                val response = queryEvaluator.evaluateQuery(query)
                sendResponse(response)
            } catch (e: Exception) {
                sendError("query_processing_error", "Failed to process query: ${e.message}")
            }
        }
    }

    private fun handleHeartbeat() {
        val message = JSONObject().apply {
            put("type", "heartbeat")
            put("device_id", "current_device_id") // TODO: Get actual device ID
            put("timestamp", System.currentTimeMillis())
            put("status", "online")
            put("performance_metrics", JSONObject()) // TODO: Get actual metrics
        }.toString()

        webSocket?.send(message)
    }

    private fun sendResponse(response: QueryResponse) {
        val message = JSONObject().apply {
            put("type", "query_response")
            put("response_id", response.responseId)
            put("query_id", response.queryId)
            put("device_id", response.deviceId)
            put("response_payload", JSONObject(response.responsePayload))
            put("data_tier_provided", response.dataTierProvided)
            put("processing_timestamp", response.processingTimestamp)
            put("delivery_timestamp", response.deliveryTimestamp)
            put("response_quality_score", response.responseQualityScore)
            put("schema_version", response.schemaVersion)
        }.toString()

        webSocket?.send(message)
    }

    private fun sendError(errorType: String, message: String) {
        val error = JSONObject().apply {
            put("type", "error")
            put("error_type", errorType)
            put("message", message)
            put("timestamp", System.currentTimeMillis())
        }.toString()

        webSocket?.send(error)
    }

    private fun reconnect() {
        // TODO: Implement reconnection logic with exponential backoff
    }

    private fun JSONObject.toMap(): Map<String, Any> {
        val map = mutableMapOf<String, Any>()
        keys().forEach { key ->
            map[key] = get(key)
        }
        return map
    }
} 