package com.junkvpn.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent

/** Copies [text] to the system clipboard (the OS confirms on API 33+). */
fun copyToClipboard(context: Context, label: String, text: String) {
    val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    manager.setPrimaryClip(ClipData.newPlainText(label, text))
}

/** Opens the system share sheet with [text] pre-filled. */
fun shareText(context: Context, chooserTitle: String, text: String): String? {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    return try {
        context.startActivity(Intent.createChooser(intent, chooserTitle))
        null
    } catch (t: Throwable) {
        t.message ?: "Nothing can handle sharing right now"
    }
}
