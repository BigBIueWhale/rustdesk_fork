package com.carriez.flutter_hbb

/**
 * Handle remote input and dispatch android gesture
 *
 * Inspired by [droidVNC-NG] https://github.com/bk138/droidVNC-NG
 */

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.EditText
import android.view.accessibility.AccessibilityEvent
import android.view.ViewGroup.LayoutParams
import android.view.accessibility.AccessibilityNodeInfo
import android.view.KeyEvent as KeyEventAndroid
import android.view.ViewConfiguration
import android.graphics.Rect
import android.media.AudioManager
import android.accessibilityservice.AccessibilityServiceInfo
import android.accessibilityservice.AccessibilityServiceInfo.FLAG_INPUT_METHOD_EDITOR
import android.accessibilityservice.AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
import android.view.inputmethod.EditorInfo
import androidx.annotation.RequiresApi
import java.util.*
import java.lang.Character
import kotlin.math.abs
import kotlin.math.max
import hbb.MessageOuterClass.KeyEvent
import hbb.MessageOuterClass.KeyboardMode
import hbb.KeyEventConverter

// const val BUTTON_UP = 2
// const val BUTTON_BACK = 0x08

const val LEFT_DOWN = 9
const val LEFT_MOVE = 8
const val LEFT_UP = 10
const val RIGHT_UP = 18
// (BUTTON_BACK << 3) | BUTTON_UP
const val BACK_UP = 66
const val WHEEL_BUTTON_DOWN = 33
const val WHEEL_BUTTON_UP = 34
const val WHEEL_DOWN = 523331
const val WHEEL_UP = 963

const val TOUCH_SCALE_START = 1
const val TOUCH_SCALE = 2
const val TOUCH_SCALE_END = 3
const val TOUCH_PAN_START = 4
const val TOUCH_PAN_UPDATE = 5
const val TOUCH_PAN_END = 6

const val WHEEL_STEP = 120
const val WHEEL_DURATION = 50L
const val LONG_TAP_DELAY = 200L
private const val MAX_PENDING_WHEEL_ACTIONS = 32
private const val MAX_PENDING_KEY_ACTIONS = 64

class InputService : AccessibilityService() {

    companion object {
        @Volatile
        var ctx: InputService? = null
        val isOpen: Boolean
            get() = ctx != null
    }

    private val logTag = "input service"
    private var leftIsDown = false
    private var touchPath = Path()
    private var stroke: GestureDescription.StrokeDescription? = null
    private var lastTouchGestureStartTime = 0L
    private var mouseX = 0
    private var mouseY = 0
    private val mainHandler = Handler(Looper.getMainLooper())
    private val activeInputOwners = mutableSetOf<ControlledInputOwner>()
    private val wheelActions =
        ExactOwnerBoundedQueue<GestureDescription>(MAX_PENDING_WHEEL_ACTIONS)
    private val keyActions = ExactOwnerBoundedQueue<KeyEvent>(MAX_PENDING_KEY_ACTIONS)
    private var wheelActionInFlight: OwnedControlledInput<GestureDescription>? = null
    private var wheelDrainPosted = false
    private var keyDrainPosted = false
    private var destroyed = false
    private var pointerOwner: ControlledInputOwner? = null
    private var pointerSequence: PointerSequence? = null
    private var pendingLongPress: PendingOwnedAction? = null
    private var pendingRecentAction: PendingOwnedAction? = null
    private var delayedActionSequence = 0L
    // 100(tap timeout) + 400(long press timeout)
    private val longPressDuration = ViewConfiguration.getTapTimeout().toLong() + ViewConfiguration.getLongPressTimeout().toLong()

    private var isWaitingLongPress = false

    private var fakeEditTextForTextStateCalculation: EditText? = null

    private var lastX = 0
    private var lastY = 0

    private val volumeController: VolumeController by lazy { VolumeController(applicationContext.getSystemService(AUDIO_SERVICE) as AudioManager) }

    private data class PendingOwnedAction(
        val owner: ControlledInputOwner,
        val sequence: Long,
        val runnable: Runnable,
    )

    private enum class PointerSequence {
        MOUSE,
        TOUCH,
    }

    private val wheelDrain = Runnable { drainWheelAction() }
    private val keyDrain = Runnable { drainKeyAction() }

    @Synchronized
    internal fun registerInputOwner(owner: ControlledInputOwner): Boolean {
        if (destroyed || !owner.isValid) {
            return false
        }
        activeInputOwners.add(owner)
        return true
    }

    @Synchronized
    internal fun retireInputOwner(owner: ControlledInputOwner) {
        activeInputOwners.remove(owner)
        wheelActions.removeOwner(owner)
        keyActions.removeOwner(owner)
        cancelLongPress(owner)
        cancelRecentAction(owner)
        if (pointerOwner == owner) {
            finishAndResetPointerSequence()
        }
    }

    @Synchronized
    internal fun retireServiceGeneration(serviceGeneration: Long) {
        val owners = activeInputOwners
            .filter { it.serviceGeneration == serviceGeneration }
            .toList()
        for (owner in owners) {
            retireInputOwner(owner)
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    @Synchronized
    internal fun onMouseInput(
        owner: ControlledInputOwner,
        mask: Int,
        _x: Int,
        _y: Int,
    ): Boolean {
        if (destroyed || owner !in activeInputOwners) {
            return false
        }
        val activePointerOwner = pointerOwner
        if (activePointerOwner != null) {
            if (activePointerOwner != owner ||
                pointerSequence != PointerSequence.MOUSE ||
                (mask != 0 && mask != LEFT_MOVE && mask != LEFT_UP)
            ) {
                return false
            }
        }
        val x = max(0, _x)
        val y = max(0, _y)

        if (mask == 0 || mask == LEFT_MOVE) {
            val oldX = mouseX
            val oldY = mouseY
            mouseX = x * SCREEN_INFO.scale
            mouseY = y * SCREEN_INFO.scale
            if (isWaitingLongPress) {
                val delta = abs(oldX - mouseX) + abs(oldY - mouseY)
                Log.d(logTag,"delta:$delta")
                if (delta > 8) {
                    isWaitingLongPress = false
                }
            }
        }

        // left button down, was up
        if (mask == LEFT_DOWN) {
            if (leftIsDown || pointerOwner != null) {
                return false
            }
            pointerOwner = owner
            pointerSequence = PointerSequence.MOUSE
            isWaitingLongPress = true
            if (!scheduleLongPress(owner)) {
                isWaitingLongPress = false
                pointerOwner = null
                pointerSequence = null
                return false
            }

            leftIsDown = true
            startGesture(mouseX, mouseY)
            return true
        }

        // left down, was down
        if (leftIsDown) {
            if (pointerOwner != owner) {
                return false
            }
            continueGesture(mouseX, mouseY)
        }

        // left up, was down
        if (mask == LEFT_UP) {
            if (leftIsDown) {
                leftIsDown = false
                isWaitingLongPress = false
                cancelLongPress(owner)
                endGesture(mouseX, mouseY)
                pointerOwner = null
                pointerSequence = null
                return true
            }
        }

        if (mask == RIGHT_UP) {
            longPress(mouseX, mouseY)
            return true
        }

        if (mask == BACK_UP) {
            performGlobalAction(GLOBAL_ACTION_BACK)
            return true
        }

        // long WHEEL_BUTTON_DOWN -> GLOBAL_ACTION_RECENTS
        if (mask == WHEEL_BUTTON_DOWN) {
            if (pendingRecentAction != null) {
                return false
            }
            return scheduleRecentAction(owner)
        }

        // wheel button up
        if (mask == WHEEL_BUTTON_UP) {
            val pending = pendingRecentAction
            if (pending != null) {
                if (pending.owner != owner) {
                    return false
                }
                cancelRecentAction(owner)
                performGlobalAction(GLOBAL_ACTION_HOME)
            }
            return true
        }

        if (mask == WHEEL_DOWN) {
            if (mouseY < WHEEL_STEP) {
                return true
            }
            val path = Path()
            path.moveTo(mouseX.toFloat(), mouseY.toFloat())
            path.lineTo(mouseX.toFloat(), (mouseY - WHEEL_STEP).toFloat())
            val stroke = GestureDescription.StrokeDescription(
                path,
                0,
                WHEEL_DURATION
            )
            val builder = GestureDescription.Builder()
            builder.addStroke(stroke)
            return enqueueWheelAction(owner, builder.build())
        }

        if (mask == WHEEL_UP) {
            if (mouseY < WHEEL_STEP) {
                return true
            }
            val path = Path()
            path.moveTo(mouseX.toFloat(), mouseY.toFloat())
            path.lineTo(mouseX.toFloat(), (mouseY + WHEEL_STEP).toFloat())
            val stroke = GestureDescription.StrokeDescription(
                path,
                0,
                WHEEL_DURATION
            )
            val builder = GestureDescription.Builder()
            builder.addStroke(stroke)
            return enqueueWheelAction(owner, builder.build())
        }
        return true
    }

    @RequiresApi(Build.VERSION_CODES.N)
    @Synchronized
    internal fun onTouchInput(
        owner: ControlledInputOwner,
        mask: Int,
        _x: Int,
        _y: Int,
    ): Boolean {
        if (destroyed || owner !in activeInputOwners) {
            return false
        }
        when (mask) {
            TOUCH_PAN_UPDATE -> {
                if (pointerOwner != owner || pointerSequence != PointerSequence.TOUCH) {
                    return false
                }
                mouseX -= _x * SCREEN_INFO.scale
                mouseY -= _y * SCREEN_INFO.scale
                mouseX = max(0, mouseX);
                mouseY = max(0, mouseY);
                continueGesture(mouseX, mouseY)
            }
            TOUCH_PAN_START -> {
                if (pointerOwner != null) {
                    return false
                }
                pointerOwner = owner
                pointerSequence = PointerSequence.TOUCH
                mouseX = max(0, _x) * SCREEN_INFO.scale
                mouseY = max(0, _y) * SCREEN_INFO.scale
                startGesture(mouseX, mouseY)
            }
            TOUCH_PAN_END -> {
                if (pointerOwner != owner || pointerSequence != PointerSequence.TOUCH) {
                    return false
                }
                endGesture(mouseX, mouseY)
                pointerOwner = null
                pointerSequence = null
                mouseX = max(0, _x) * SCREEN_INFO.scale
                mouseY = max(0, _y) * SCREEN_INFO.scale
            }
            else -> {}
        }
        return true
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun enqueueWheelAction(
        owner: ControlledInputOwner,
        gesture: GestureDescription,
    ): Boolean {
        if (!wheelActions.offer(owner, gesture)) {
            Log.w(logTag, "Rejecting Android input owner after wheel queue saturation")
            return false
        }
        if (scheduleWheelDrain()) {
            return true
        }
        wheelActions.removeOwner(owner)
        return false
    }

    @Synchronized
    private fun scheduleWheelDrain(): Boolean {
        if (destroyed || wheelActionInFlight != null || wheelDrainPosted || wheelActions.size == 0) {
            return !destroyed
        }
        wheelDrainPosted = true
        if (mainHandler.post(wheelDrain)) {
            return true
        }
        wheelDrainPosted = false
        return false
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun drainWheelAction() {
        synchronized(this) {
            wheelDrainPosted = false
            if (destroyed || wheelActionInFlight != null) {
                return
            }
            var next = wheelActions.poll()
            while (next != null && next.owner !in activeInputOwners) {
                next = wheelActions.poll()
            }
            val admitted = next ?: return
            wheelActionInFlight = admitted
            val callback = object : GestureResultCallback() {
                override fun onCompleted(gestureDescription: GestureDescription) {
                    completeWheelAction(admitted)
                }

                override fun onCancelled(gestureDescription: GestureDescription) {
                    completeWheelAction(admitted)
                }
            }
            if (!dispatchGesture(admitted.value, callback, mainHandler)) {
                completeWheelAction(admitted)
            }
        }
    }

    @Synchronized
    private fun completeWheelAction(completed: OwnedControlledInput<GestureDescription>) {
        if (wheelActionInFlight !== completed) {
            return
        }
        wheelActionInFlight = null
        scheduleWheelDrain()
    }

    private fun nextDelayedActionSequence(): Long? {
        if (delayedActionSequence == Long.MAX_VALUE) {
            return null
        }
        delayedActionSequence += 1
        return delayedActionSequence
    }

    @Synchronized
    private fun scheduleLongPress(owner: ControlledInputOwner): Boolean {
        cancelLongPress(null)
        val sequence = nextDelayedActionSequence() ?: return false
        val runnable = Runnable { runLongPress(owner, sequence) }
        pendingLongPress = PendingOwnedAction(owner, sequence, runnable)
        if (mainHandler.postDelayed(runnable, longPressDuration)) {
            return true
        }
        pendingLongPress = null
        return false
    }

    @Synchronized
    private fun runLongPress(owner: ControlledInputOwner, sequence: Long) {
        val pending = pendingLongPress
        if (pending?.owner != owner || pending.sequence != sequence) {
            return
        }
        pendingLongPress = null
        if (destroyed ||
            owner !in activeInputOwners ||
            pointerOwner != owner ||
            !leftIsDown ||
            !isWaitingLongPress
        ) {
            return
        }
        isWaitingLongPress = false
        continueGesture(mouseX, mouseY)
    }

    @Synchronized
    private fun cancelLongPress(owner: ControlledInputOwner?) {
        val pending = pendingLongPress ?: return
        if (owner != null && pending.owner != owner) {
            return
        }
        mainHandler.removeCallbacks(pending.runnable)
        pendingLongPress = null
    }

    @Synchronized
    private fun scheduleRecentAction(owner: ControlledInputOwner): Boolean {
        val sequence = nextDelayedActionSequence() ?: return false
        val runnable = Runnable { runRecentAction(owner, sequence) }
        pendingRecentAction = PendingOwnedAction(owner, sequence, runnable)
        if (mainHandler.postDelayed(runnable, LONG_TAP_DELAY)) {
            return true
        }
        pendingRecentAction = null
        return false
    }

    @Synchronized
    private fun runRecentAction(owner: ControlledInputOwner, sequence: Long) {
        val pending = pendingRecentAction
        if (destroyed ||
            pending?.owner != owner ||
            pending.sequence != sequence ||
            owner !in activeInputOwners
        ) {
            return
        }
        pendingRecentAction = null
        performGlobalAction(GLOBAL_ACTION_RECENTS)
    }

    @Synchronized
    private fun cancelRecentAction(owner: ControlledInputOwner?) {
        val pending = pendingRecentAction ?: return
        if (owner != null && pending.owner != owner) {
            return
        }
        mainHandler.removeCallbacks(pending.runnable)
        pendingRecentAction = null
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun finishAndResetPointerSequence() {
        cancelLongPress(pointerOwner)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && stroke != null) {
            endGesture(mouseX, mouseY)
        }
        leftIsDown = false
        isWaitingLongPress = false
        pointerOwner = null
        pointerSequence = null
        stroke = null
        touchPath.reset()
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun performClick(x: Int, y: Int, duration: Long) {
        val path = Path()
        path.moveTo(x.toFloat(), y.toFloat())
        try {
            val longPressStroke = GestureDescription.StrokeDescription(path, 0, duration)
            val builder = GestureDescription.Builder()
            builder.addStroke(longPressStroke)
            Log.d(logTag, "performClick x:$x y:$y time:$duration")
            dispatchGesture(builder.build(), null, null)
        } catch (e: Exception) {
            Log.e(logTag, "performClick, error:$e")
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun longPress(x: Int, y: Int) {
        performClick(x, y, longPressDuration)
    }

    private fun startGesture(x: Int, y: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            touchPath.reset()
        } else {
            touchPath = Path()
        }
        touchPath.moveTo(x.toFloat(), y.toFloat())
        lastTouchGestureStartTime = System.currentTimeMillis()
        lastX = x
        lastY = y
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun doDispatchGesture(x: Int, y: Int, willContinue: Boolean) {
        touchPath.lineTo(x.toFloat(), y.toFloat())
        var duration = System.currentTimeMillis() - lastTouchGestureStartTime
        if (duration <= 0) {
            duration = 1
        }
        try {
            if (stroke == null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    stroke = GestureDescription.StrokeDescription(
                        touchPath,
                        0,
                        duration,
                        willContinue
                    )
                } else {
                    stroke = GestureDescription.StrokeDescription(
                        touchPath,
                        0,
                        duration
                    )
                }
            } else {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    stroke = stroke?.continueStroke(touchPath, 0, duration, willContinue)
                } else {
                    stroke = null
                    stroke = GestureDescription.StrokeDescription(
                        touchPath,
                        0,
                        duration
                    )
                }
            }
            stroke?.let {
                val builder = GestureDescription.Builder()
                builder.addStroke(it)
                Log.d(logTag, "doDispatchGesture x:$x y:$y time:$duration")
                dispatchGesture(builder.build(), null, null)
            }
        } catch (e: Exception) {
            Log.e(logTag, "doDispatchGesture, willContinue:$willContinue, error:$e")
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun continueGesture(x: Int, y: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            doDispatchGesture(x, y, true)
            touchPath.reset()
            touchPath.moveTo(x.toFloat(), y.toFloat())
            lastTouchGestureStartTime = System.currentTimeMillis()
            lastX = x
            lastY = y
        } else {
            touchPath.lineTo(x.toFloat(), y.toFloat())
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun endGestureBelowO(x: Int, y: Int) {
        try {
            touchPath.lineTo(x.toFloat(), y.toFloat())
            var duration = System.currentTimeMillis() - lastTouchGestureStartTime
            if (duration <= 0) {
                duration = 1
            }
            val stroke = GestureDescription.StrokeDescription(
                touchPath,
                0,
                duration
            )
            val builder = GestureDescription.Builder()
            builder.addStroke(stroke)
            Log.d(logTag, "end gesture x:$x y:$y time:$duration")
            dispatchGesture(builder.build(), null, null)
        } catch (e: Exception) {
            Log.e(logTag, "endGesture error:$e")
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun endGesture(x: Int, y: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            doDispatchGesture(x, y, false)
            touchPath.reset()
            stroke = null
        } else {
            endGestureBelowO(x, y)
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    @Synchronized
    internal fun onKeyEvent(owner: ControlledInputOwner, data: ByteArray): Boolean {
        if (destroyed || owner !in activeInputOwners) {
            return false
        }
        val keyEvent = try {
            KeyEvent.parseFrom(data)
        } catch (e: Exception) {
            Log.w(logTag, "Rejected malformed Android key input", e)
            return false
        }
        if (!keyActions.offer(owner, keyEvent)) {
            Log.w(logTag, "Rejecting Android input owner after key queue saturation")
            return false
        }
        if (scheduleKeyDrain()) {
            return true
        }
        keyActions.removeOwner(owner)
        return false
    }

    @Synchronized
    private fun scheduleKeyDrain(): Boolean {
        if (destroyed || keyDrainPosted || keyActions.size == 0) {
            return !destroyed
        }
        keyDrainPosted = true
        if (mainHandler.post(keyDrain)) {
            return true
        }
        keyDrainPosted = false
        return false
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun drainKeyAction() {
        synchronized(this) {
            keyDrainPosted = false
            if (destroyed) {
                return
            }
            var next = keyActions.poll()
            while (next != null && next.owner !in activeInputOwners) {
                next = keyActions.poll()
            }
            if (next != null) {
                processKeyEvent(next.value)
            }
            scheduleKeyDrain()
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun processKeyEvent(keyEvent: KeyEvent) {
        val keyboardMode = keyEvent.getMode()

        var textToCommit: String? = null

        // [down] indicates the key's state(down or up).
        // [press] indicates a click event(down and up).
        // https://github.com/rustdesk/rustdesk/blob/3a7594755341f023f56fa4b6a43b60d6b47df88d/flutter/lib/models/input_model.dart#L688
        if (keyEvent.hasSeq()) {
            textToCommit = keyEvent.getSeq()
        } else if (keyboardMode == KeyboardMode.Legacy) {
            if (keyEvent.hasChr() && (keyEvent.getDown() || keyEvent.getPress())) {
                val chr = keyEvent.getChr()
                if (chr != null) {
                    textToCommit = String(Character.toChars(chr))
                }
            }
        } else if (keyboardMode == KeyboardMode.Translate) {
        } else {
        }

        Log.d(logTag, "onKeyEvent $keyEvent textToCommit:$textToCommit")

        var ke: KeyEventAndroid? = null
        if (Build.VERSION.SDK_INT < 33 || textToCommit == null) {
            ke = KeyEventConverter.toAndroidKeyEvent(keyEvent)
        }
        ke?.let { event ->
            if (tryHandleVolumeKeyEvent(event)) {
                return
            } else if (tryHandlePowerKeyEvent(event)) {
                return
            }
        }

        if (Build.VERSION.SDK_INT >= 33) {
            getInputMethod()?.let { inputMethod ->
                inputMethod.getCurrentInputConnection()?.let { inputConnection ->
                    if (textToCommit != null) {
                        textToCommit?.let { text ->
                            inputConnection.commitText(text, 1, null)
                        }
                    } else {
                        ke?.let { event ->
                            inputConnection.sendKeyEvent(event)
                            if (keyEvent.getPress()) {
                                val actionUpEvent = KeyEventAndroid(KeyEventAndroid.ACTION_UP, event.keyCode)
                                inputConnection.sendKeyEvent(actionUpEvent)
                            }
                        }
                    }
                }
            }
        } else {
            ke?.let { event ->
                val possibleNodes = possibleAccessibiltyNodes()
                Log.d(logTag, "possibleNodes:$possibleNodes")
                for (item in possibleNodes) {
                    val success = trySendKeyEvent(event, item, textToCommit)
                    if (success) {
                        if (keyEvent.getPress()) {
                            val actionUpEvent = KeyEventAndroid(KeyEventAndroid.ACTION_UP, event.keyCode)
                            trySendKeyEvent(actionUpEvent, item, textToCommit)
                        }
                        break
                    }
                }
            }
        }
    }

    private fun tryHandleVolumeKeyEvent(event: KeyEventAndroid): Boolean {
        when (event.keyCode) {
            KeyEventAndroid.KEYCODE_VOLUME_UP -> {
                if (event.action == KeyEventAndroid.ACTION_DOWN) {
                    volumeController.raiseVolume(null, true, AudioManager.STREAM_SYSTEM)
                }
                return true
            }
            KeyEventAndroid.KEYCODE_VOLUME_DOWN -> {
                if (event.action == KeyEventAndroid.ACTION_DOWN) {
                    volumeController.lowerVolume(null, true, AudioManager.STREAM_SYSTEM)
                }
                return true
            }
            KeyEventAndroid.KEYCODE_VOLUME_MUTE -> {
                if (event.action == KeyEventAndroid.ACTION_DOWN) {
                    volumeController.toggleMute(true, AudioManager.STREAM_SYSTEM)
                }
                return true
            }
            else -> {
                return false
            }
        }
    }

    private fun tryHandlePowerKeyEvent(event: KeyEventAndroid): Boolean {
        if (event.keyCode == KeyEventAndroid.KEYCODE_POWER) {
            // Perform power dialog action when action is up
            if (event.action == KeyEventAndroid.ACTION_UP) {
                performGlobalAction(GLOBAL_ACTION_POWER_DIALOG);
            }
            return true
        }
        return false
    }

    private fun insertAccessibilityNode(list: LinkedList<AccessibilityNodeInfo>, node: AccessibilityNodeInfo) {
        if (node == null) {
            return
        }
        if (list.contains(node)) {
            return
        }
        list.add(node)
    }

    private fun findChildNode(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        if (node == null) {
            return null
        }
        if (node.isEditable() && node.isFocusable()) {
            return node
        }
        val childCount = node.getChildCount()
        for (i in 0 until childCount) {
            val child = node.getChild(i)
            if (child != null) {
                if (child.isEditable() && child.isFocusable()) {
                    return child
                }
                if (Build.VERSION.SDK_INT < 33) {
                    child.recycle()
                }
            }
        }
        for (i in 0 until childCount) {
            val child = node.getChild(i)
            if (child != null) {
                val result = findChildNode(child)
                if (Build.VERSION.SDK_INT < 33) {
                    if (child != result) {
                        child.recycle()
                    }
                }
                if (result != null) {
                    return result
                }
            }
        }
        return null
    }

    private fun possibleAccessibiltyNodes(): LinkedList<AccessibilityNodeInfo> {
        val linkedList = LinkedList<AccessibilityNodeInfo>()
        val latestList = LinkedList<AccessibilityNodeInfo>()

        val focusInput = findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        var focusAccessibilityInput = findFocus(AccessibilityNodeInfo.FOCUS_ACCESSIBILITY)

        val rootInActiveWindow = getRootInActiveWindow()

        Log.d(logTag, "focusInput:$focusInput focusAccessibilityInput:$focusAccessibilityInput rootInActiveWindow:$rootInActiveWindow")

        if (focusInput != null) {
            if (focusInput.isFocusable() && focusInput.isEditable()) {
                insertAccessibilityNode(linkedList, focusInput)
            } else {
                insertAccessibilityNode(latestList, focusInput)
            }
        }

        if (focusAccessibilityInput != null) {
            if (focusAccessibilityInput.isFocusable() && focusAccessibilityInput.isEditable()) {
                insertAccessibilityNode(linkedList, focusAccessibilityInput)
            } else {
                insertAccessibilityNode(latestList, focusAccessibilityInput)
            }
        }

        val childFromFocusInput = findChildNode(focusInput)
        Log.d(logTag, "childFromFocusInput:$childFromFocusInput")

        if (childFromFocusInput != null) {
            insertAccessibilityNode(linkedList, childFromFocusInput)
        }

        val childFromFocusAccessibilityInput = findChildNode(focusAccessibilityInput)
        if (childFromFocusAccessibilityInput != null) {
            insertAccessibilityNode(linkedList, childFromFocusAccessibilityInput)
        }
        Log.d(logTag, "childFromFocusAccessibilityInput:$childFromFocusAccessibilityInput")

        if (rootInActiveWindow != null) {
            insertAccessibilityNode(linkedList, rootInActiveWindow)
        }

        for (item in latestList) {
            insertAccessibilityNode(linkedList, item)
        }

        return linkedList
    }

    private fun trySendKeyEvent(event: KeyEventAndroid, node: AccessibilityNodeInfo, textToCommit: String?): Boolean {
        node.refresh()
        this.fakeEditTextForTextStateCalculation?.setSelection(0,0)
        this.fakeEditTextForTextStateCalculation?.setText(null)

        val text = node.getText()
        var isShowingHint = false
        if (Build.VERSION.SDK_INT >= 26) {
            isShowingHint = node.isShowingHintText()
        }

        var textSelectionStart = node.textSelectionStart
        var textSelectionEnd = node.textSelectionEnd

        if (text != null) {
            if (textSelectionStart > text.length) {
                textSelectionStart = text.length
            }
            if (textSelectionEnd > text.length) {
                textSelectionEnd = text.length
            }
            if (textSelectionStart > textSelectionEnd) {
                textSelectionStart = textSelectionEnd
            }
        }

        var success = false

        Log.d(logTag, "existing text:$text textToCommit:$textToCommit textSelectionStart:$textSelectionStart textSelectionEnd:$textSelectionEnd")

        if (textToCommit != null) {
            if ((textSelectionStart == -1) || (textSelectionEnd == -1)) {
                val newText = textToCommit
                this.fakeEditTextForTextStateCalculation?.setText(newText)
                success = updateTextForAccessibilityNode(node)
            } else if (text != null) {
                this.fakeEditTextForTextStateCalculation?.setText(text)
                this.fakeEditTextForTextStateCalculation?.setSelection(
                    textSelectionStart,
                    textSelectionEnd
                )
                this.fakeEditTextForTextStateCalculation?.text?.insert(textSelectionStart, textToCommit)
                success = updateTextAndSelectionForAccessibiltyNode(node)
            }
        } else {
            if (isShowingHint) {
                this.fakeEditTextForTextStateCalculation?.setText(null)
            } else {
                this.fakeEditTextForTextStateCalculation?.setText(text)
            }
            if (textSelectionStart != -1 && textSelectionEnd != -1) {
                Log.d(logTag, "setting selection $textSelectionStart $textSelectionEnd")
                this.fakeEditTextForTextStateCalculation?.setSelection(
                    textSelectionStart,
                    textSelectionEnd
                )
            }

            this.fakeEditTextForTextStateCalculation?.let {
                // This is essiential to make sure layout object is created. OnKeyDown may not work if layout is not created.
                val rect = Rect()
                node.getBoundsInScreen(rect)

                it.layout(rect.left, rect.top, rect.right, rect.bottom)
                it.onPreDraw()
                if (event.action == KeyEventAndroid.ACTION_DOWN) {
                    val succ = it.onKeyDown(event.getKeyCode(), event)
                    Log.d(logTag, "onKeyDown $succ")
                } else if (event.action == KeyEventAndroid.ACTION_UP) {
                    val success = it.onKeyUp(event.getKeyCode(), event)
                    Log.d(logTag, "keyup $success")
                } else {}
            }

            success = updateTextAndSelectionForAccessibiltyNode(node)
        }
        return success
    }

    fun updateTextForAccessibilityNode(node: AccessibilityNodeInfo): Boolean {
        var success = false
        this.fakeEditTextForTextStateCalculation?.text?.let {
            val arguments = Bundle()
            arguments.putCharSequence(
                AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                it.toString()
            )
            success = node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments)
        }
        return success
    }

    fun updateTextAndSelectionForAccessibiltyNode(node: AccessibilityNodeInfo): Boolean {
        var success = updateTextForAccessibilityNode(node)

        if (success) {
            val selectionStart = this.fakeEditTextForTextStateCalculation?.selectionStart
            val selectionEnd = this.fakeEditTextForTextStateCalculation?.selectionEnd

            if (selectionStart != null && selectionEnd != null) {
                val arguments = Bundle()
                arguments.putInt(
                    AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_START_INT,
                    selectionStart
                )
                arguments.putInt(
                    AccessibilityNodeInfo.ACTION_ARGUMENT_SELECTION_END_INT,
                    selectionEnd
                )
                success = node.performAction(AccessibilityNodeInfo.ACTION_SET_SELECTION, arguments)
                Log.d(logTag, "Update selection to $selectionStart $selectionEnd success:$success")
            }
        }

        return success
    }


    override fun onAccessibilityEvent(event: AccessibilityEvent) {
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        synchronized(this) {
            destroyed = false
        }
        ctx = this
        val info = AccessibilityServiceInfo()
        if (Build.VERSION.SDK_INT >= 33) {
            info.flags = FLAG_INPUT_METHOD_EDITOR or FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        } else {
            info.flags = FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        }
        setServiceInfo(info)
        fakeEditTextForTextStateCalculation = EditText(this)
        // Size here doesn't matter, we won't show this view.
        fakeEditTextForTextStateCalculation?.layoutParams = LayoutParams(100, 100)
        fakeEditTextForTextStateCalculation?.onPreDraw()
        val layout = fakeEditTextForTextStateCalculation?.getLayout()
        Log.d(logTag, "fakeEditTextForTextStateCalculation layout:$layout")
        Log.d(logTag, "onServiceConnected!")
    }

    override fun onDestroy() {
        synchronized(this) {
            destroyed = true
            activeInputOwners.clear()
            wheelActions.clear()
            keyActions.clear()
            wheelActionInFlight = null
            wheelDrainPosted = false
            keyDrainPosted = false
            cancelLongPress(null)
            cancelRecentAction(null)
            pointerOwner = null
            pointerSequence = null
            leftIsDown = false
            isWaitingLongPress = false
            stroke = null
            touchPath.reset()
            fakeEditTextForTextStateCalculation = null
            mainHandler.removeCallbacks(wheelDrain)
            mainHandler.removeCallbacks(keyDrain)
        }
        if (ctx === this) {
            ctx = null
        }
        super.onDestroy()
    }

    override fun onInterrupt() {
        synchronized(this) {
            val owners = activeInputOwners.toList()
            for (owner in owners) {
                retireInputOwner(owner)
            }
        }
    }
}
