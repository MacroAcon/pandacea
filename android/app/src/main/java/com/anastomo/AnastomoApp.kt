package com.anastomo

import android.app.Application
import android.content.Context

class AnastomoApp : Application() {
    companion object {
        lateinit var instance: AnastomoApp
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }
} 