package com.carriez.flutter_hbb

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Timer
import java.util.TimerTask

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.util.Log
import androidx.annotation.Keep

import hbb.MessageOuterClass.ClipboardFormat
import hbb.MessageOuterClass.Clipboard
import hbb.MessageOuterClass.MultiClipboards

import ffi.FFI

private const val MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES = 64 * 1024 * 1024
private const val MAX_ANDROID_CLIPBOARD_PAYLOAD_CHARS = MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES / 4
private const val MAX_ANDROID_CLIPBOARD_PROTO_BYTES = 64 * 1024 * 1024
private const val MAX_ANDROID_CLIPBOARD_UPDATE_BYTES = 1 + MAX_ANDROID_CLIPBOARD_PROTO_BYTES
private const val ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES = 16
private const val ANDROID_SANITIZED_CLIPBOARD_VERSION = 1
private val ANDROID_SANITIZED_CLIPBOARD_MAGIC = byteArrayOf('R'.code.toByte(), 'D'.code.toByte(), 'C'.code.toByte(), 'B'.code.toByte())

class RdClipboardManager(private val clipboardManager: ClipboardManager) {
    private val logTag = "RdClipboardManager"
    private val supportedMimeTypes = arrayOf(
        ClipDescription.MIMETYPE_TEXT_PLAIN,
        ClipDescription.MIMETYPE_TEXT_HTML
    )

    // 1. Avoid listening to the same clipboard data updated by `rustUpdateSanitizedClipboard`.
    // 2. Avoid sending the clipboard data before enabling client clipboard.
    //    1) Disable clipboard
    //    2) Copy text "a"
    //    3) Enable clipboard
    //    4) Switch to another app
    //    5) Switch back to the app
    //    6) "a" should not be sent to the client, because it's copied before enabling clipboard
    //
    // It's okay to that `rustEnableClientClipboard(false)` is called after `rustUpdateSanitizedClipboard`,
    // though the `lastUpdatedClipData` will be set to null once.
    private var lastUpdatedClipData: ClipData? = null
    private var isClientEnabled = true;
    private var _isCaptureStarted = false;

    val isCaptureStarted: Boolean
        get() = _isCaptureStarted

    fun checkPrimaryClip(isClient: Boolean) {
        val clipData = clipboardManager.primaryClip
        if (clipData != null && clipData.itemCount > 0) {
            // Only handle the first item in the clipboard for now.
            val clip = clipData.getItemAt(0)
            // Ignore the `isClipboardDataEqual()` check if it's a host operation.
            // Because it's an action manually triggered by the user.
            if (isClient) {
                if (lastUpdatedClipData != null && isClipboardDataEqual(clipData, lastUpdatedClipData!!)) {
                    Log.d(logTag, "Clipboard data is the same as last update, ignore")
                    return
                }
            }
            val mimeTypeCount = clipData.description.getMimeTypeCount()
            val mimeTypes = mutableListOf<String>()
            for (i in 0 until mimeTypeCount) {
                mimeTypes.add(clipData.description.getMimeType(i))
            }
            var text: CharSequence? = null;
            var html: String? = null;
            if (isSupportedMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)) {
                text = clip?.text
            }
            if (isSupportedMimeType(ClipDescription.MIMETYPE_TEXT_HTML)) {
                text = clip?.text
                html = clip?.htmlText
            }
            var count = 0
            val clips = MultiClipboards.newBuilder()
            if (text != null) {
                val content = boundedUtf8Content(text, "text")
                if (content != null) {
                    clips.addClipboards(Clipboard.newBuilder().setFormat(ClipboardFormat.Text).setContent(content).build())
                    count++
                }
            }
            if (html != null) {
                val content = boundedUtf8Content(html, "html")
                if (content != null) {
                    clips.addClipboards(Clipboard.newBuilder().setFormat(ClipboardFormat.Html).setContent(content).build())
                    count++
                }
            }
            if (count > 0) {
                val clipsMsg = clips.build()
                val clipsSize = clipsMsg.serializedSize
                val updateSize = clipsSize + 1
                if (updateSize > MAX_ANDROID_CLIPBOARD_UPDATE_BYTES) {
                    Log.w(logTag, "dropping oversized Android clipboard update before JNI: $updateSize > $MAX_ANDROID_CLIPBOARD_UPDATE_BYTES")
                    return
                }
                val clipsBytes = clipsMsg.toByteArray()
                val isClientFlag = if (isClient) 1 else 0
                val clipsBuf = ByteBuffer.allocateDirect(updateSize).apply {
                    put(isClientFlag.toByte())
                    put(clipsBytes)
                }
                clipsBuf.flip()
                lastUpdatedClipData = clipData
                Log.d(logTag, "${if (isClient) "client" else "host"}, send clipboard data to the remote")
                FFI.onClipboardUpdate(clipsBuf)
            }
        }
    }

    private fun isSupportedMimeType(mimeType: String): Boolean {
        return supportedMimeTypes.contains(mimeType)
    }

    private fun boundedUtf8Content(value: CharSequence, label: String): com.google.protobuf.ByteString? {
        if (value.length > MAX_ANDROID_CLIPBOARD_PAYLOAD_CHARS) {
            Log.w(logTag, "dropping oversized Android clipboard $label before JNI: chars=${value.length} > $MAX_ANDROID_CLIPBOARD_PAYLOAD_CHARS")
            return null
        }
        val bytes = value.toString().toByteArray(Charsets.UTF_8)
        if (bytes.size > MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES) {
            Log.w(logTag, "dropping oversized Android clipboard $label before JNI: bytes=${bytes.size} > $MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES")
            return null
        }
        return com.google.protobuf.ByteString.copyFrom(bytes)
    }

    private fun boundedClipboardBytes(bytes: ByteArray, offset: Int, length: Int, label: String): String? {
        if (length < 0 || offset < 0 || offset > bytes.size || length > bytes.size - offset) {
            Log.w(logTag, "dropping malformed Android sanitized clipboard SET $label slice before platform clipboard")
            return null
        }
        if (length > MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES) {
            Log.w(logTag, "dropping oversized Android sanitized clipboard SET $label before platform clipboard: $length > $MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES")
            return null
        }
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, offset, length).asReadOnlyBuffer())
                .toString()
        } catch (e: CharacterCodingException) {
            Log.w(logTag, "dropping malformed Android sanitized clipboard SET $label before platform clipboard", e)
            null
        }
    }

    private fun setTextHtmlClipboard(text: String, html: String?) {
        val mimeTypes = mutableListOf(ClipDescription.MIMETYPE_TEXT_PLAIN)
        if (html != null) {
            mimeTypes.add(ClipDescription.MIMETYPE_TEXT_HTML)
        }
        val clipDescription = ClipDescription("clipboard", mimeTypes.toTypedArray())
        val item = if (html == null) {
            ClipData.Item(text)
        } else {
            ClipData.Item(text, html)
        }
        val clipData = ClipData(clipDescription, item)
        lastUpdatedClipData = clipData
        clipboardManager.setPrimaryClip(clipData)
    }

    private fun isClipboardDataEqual(left: ClipData, right: ClipData): Boolean {
        if (left.description.getMimeTypeCount() != right.description.getMimeTypeCount()) {
            return false
        }
        val mimeTypeCount = left.description.getMimeTypeCount()
        for (i in 0 until mimeTypeCount) {
            if (left.description.getMimeType(i) != right.description.getMimeType(i)) {
                return false
            }
        }

        if (left.itemCount != right.itemCount) {
            return false
        }
        for (i in 0 until left.itemCount) {
            val mimeType = left.description.getMimeType(i)
            if (!isSupportedMimeType(mimeType)) {
                continue
            }
            val leftItem = left.getItemAt(i)
            val rightItem = right.getItemAt(i)
            if (mimeType == ClipDescription.MIMETYPE_TEXT_PLAIN || mimeType == ClipDescription.MIMETYPE_TEXT_HTML) {
                if (leftItem.text != rightItem.text || leftItem.htmlText != rightItem.htmlText) {
                    return false
                }
            }
        }
        return true
    }

    fun setCaptureStarted(started: Boolean) {
        _isCaptureStarted = started
    }

    @Keep
    fun rustEnableClientClipboard(enable: Boolean) {
        Log.d(logTag, "rustEnableClientClipboard: enable: $enable")
        isClientEnabled = enable
        lastUpdatedClipData = null
    }

    fun syncClipboard(isClient: Boolean) {
        Log.d(logTag, "syncClipboard: isClient: $isClient, isClientEnabled: $isClientEnabled")
        if (isClient && !isClientEnabled) {
            return
        }
        checkPrimaryClip(isClient)
    }

    @Keep
    fun rustUpdateSanitizedClipboard(payload: ByteArray) {
        if (payload.size > MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES + ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES) {
            Log.w(logTag, "dropping oversized Android sanitized clipboard SET before platform clipboard: ${payload.size}")
            return
        }
        if (payload.size < ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES) {
            Log.w(logTag, "dropping malformed Android sanitized clipboard SET before platform clipboard")
            return
        }
        if (payload[0] != ANDROID_SANITIZED_CLIPBOARD_MAGIC[0] ||
            payload[1] != ANDROID_SANITIZED_CLIPBOARD_MAGIC[1] ||
            payload[2] != ANDROID_SANITIZED_CLIPBOARD_MAGIC[2] ||
            payload[3] != ANDROID_SANITIZED_CLIPBOARD_MAGIC[3]
        ) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with bad magic")
            return
        }
        val version = payload[4].toInt() and 0xff
        val flags = payload[5].toInt() and 0xff
        if (version != ANDROID_SANITIZED_CLIPBOARD_VERSION || flags and 0xfe != 0) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with bad version or flags")
            return
        }
        if (payload[6].toInt() != 0 || payload[7].toInt() != 0) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with non-zero reserved bytes")
            return
        }
        val header = ByteBuffer.wrap(payload, 8, 8).order(ByteOrder.LITTLE_ENDIAN)
        val textLen = header.int
        val htmlLen = header.int
        if (textLen <= 0 || htmlLen < 0) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with invalid lengths")
            return
        }
        val aggregate = textLen.toLong() + htmlLen.toLong()
        if (aggregate > MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES.toLong()) {
            Log.w(logTag, "dropping oversized Android sanitized clipboard SET aggregate: $aggregate > $MAX_ANDROID_CLIPBOARD_PAYLOAD_BYTES")
            return
        }
        val expected = ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES.toLong() + aggregate
        if (payload.size.toLong() != expected) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with mismatched length")
            return
        }
        if ((flags and 1) == 0 && htmlLen != 0) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with HTML bytes but no flag")
            return
        }
        if ((flags and 1) == 1 && htmlLen == 0) {
            Log.w(logTag, "dropping Android sanitized clipboard SET with HTML flag but no HTML bytes")
            return
        }
        val textStart = ANDROID_SANITIZED_CLIPBOARD_HEADER_BYTES
        val htmlStart = textStart + textLen
        val text = boundedClipboardBytes(payload, textStart, textLen, "text") ?: return
        val html = if (htmlLen > 0) {
            boundedClipboardBytes(payload, htmlStart, htmlLen, "html") ?: return
        } else {
            null
        }
        setTextHtmlClipboard(text, html)
    }
}
