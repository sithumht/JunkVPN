package com.junkvpn.app

import android.app.Application
import android.content.Context
import com.junkvpn.app.data.AccountStore
import com.junkvpn.app.data.HistoryStore
import com.junkvpn.app.data.ScanRepository
import com.junkvpn.app.data.SettingsStore

class JunkVPN : Application() {

    lateinit var container: Container
        private set

    override fun onCreate() {
        super.onCreate()
        container = Container(this)
    }
}

/** Owns the long-lived stores and the scan engine for the whole process. */
class Container(context: Context) {
    val settings = SettingsStore(context)
    val account = AccountStore(context)
    val history = HistoryStore(context)
    val scan = ScanRepository(history, settings, account)
}
