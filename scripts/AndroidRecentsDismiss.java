package com.rustdesk.harness;

import android.app.UiAutomation;
import android.os.SystemClock;
import android.view.InputDevice;
import android.view.InputEvent;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.MotionEvent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Locale;

public final class AndroidRecentsDismiss {
    private static final int GESTURE_STEPS = 10;
    private static final int GESTURE_STEP_MILLIS = 16;
    private static final int GESTURE_EVENT_COUNT = GESTURE_STEPS + 2;
    private static final String UIAUTOMATION_WRAPPER_CLASS =
            "com.android.uiautomator.core.UiAutomationShellWrapper";
    private static final String OPEN_RECENTS_ARGUMENT = "open-recents-with-app-switch-key";
    private static final int DEFAULT_DISPLAY_ID = 0;
    private static final int OPEN_EVENT_COUNT = 2;

    private AndroidRecentsDismiss() {
    }

    private static void openPhase(String phase) {
        System.out.printf(Locale.ROOT, "ANDROID_RECENTS_OPEN_PHASE=%s%n", phase);
        System.out.flush();
    }

    private static int requiredCoordinate(String[] arguments, int index, String name) {
        if (arguments.length != 4 || !arguments[index].matches("[0-9]+")) {
            throw new IllegalArgumentException("missing or malformed coordinate: " + name);
        }
        try {
            return Integer.parseInt(arguments[index]);
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException(
                    "coordinate exceeds the integer range: " + name, error);
        }
    }

    private static Object invoke(Method method, Object target, Object... arguments)
            throws Exception {
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException error) {
            Throwable cause = error.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw error;
        }
    }

    private static MotionEvent pointerEvent(
            long downTime, long eventTime, int action, float x, float y) {
        MotionEvent.PointerProperties properties = new MotionEvent.PointerProperties();
        properties.id = 0;
        properties.toolType = MotionEvent.TOOL_TYPE_FINGER;

        MotionEvent.PointerCoords coordinates = new MotionEvent.PointerCoords();
        coordinates.pressure = 1;
        coordinates.size = 1;
        coordinates.x = x;
        coordinates.y = y;

        return MotionEvent.obtain(
                downTime,
                eventTime,
                action,
                1,
                new MotionEvent.PointerProperties[]{properties},
                new MotionEvent.PointerCoords[]{coordinates},
                0,
                0,
                1.0f,
                1.0f,
                0,
                0,
                InputDevice.SOURCE_TOUCHSCREEN,
                0);
    }

    private static void injectPointer(
            UiAutomation automation,
            Method injectInputEvent,
            long downTime,
            long eventTime,
            int action,
            float x,
            float y) throws Exception {
        MotionEvent event = pointerEvent(downTime, eventTime, action, x, y);
        try {
            Object injected = invoke(
                    injectInputEvent,
                    automation,
                    event,
                    true,
                    false);
            if (!Boolean.TRUE.equals(injected)) {
                throw new IllegalStateException("UiAutomation rejected a gesture event");
            }
        } finally {
            event.recycle();
        }
    }

    private static void injectGesture(
            UiAutomation automation,
            Method injectInputEvent,
            int startX,
            int startY,
            int endX,
            int endY) throws Exception {
        long downTime = SystemClock.uptimeMillis();
        long currentTime = downTime;
        int durationMillis = GESTURE_STEPS * GESTURE_STEP_MILLIS;

        injectPointer(
                automation,
                injectInputEvent,
                downTime,
                currentTime,
                MotionEvent.ACTION_DOWN,
                startX,
                startY);

        for (int step = 0; step < GESTURE_STEPS; step++) {
            SystemClock.sleep(GESTURE_STEP_MILLIS);
            currentTime += GESTURE_STEP_MILLIS;
            float progress = (currentTime - downTime) / (float) durationMillis;
            int x = startX + (int) (progress * (endX - startX));
            int y = startY + (int) (progress * (endY - startY));
            injectPointer(
                    automation,
                    injectInputEvent,
                    downTime,
                    currentTime,
                    MotionEvent.ACTION_MOVE,
                    x,
                    y);
        }

        injectPointer(
                automation,
                injectInputEvent,
                downTime,
                currentTime,
                MotionEvent.ACTION_UP,
                endX,
                endY);
    }

    private static void injectAppSwitchKeyEvent(
            UiAutomation automation,
            Method injectInputEvent,
            Method setDisplayId,
            Method getDisplayId,
            int action,
            long downTime) throws Exception {
        KeyEvent event = new KeyEvent(
                downTime,
                downTime,
                action,
                KeyEvent.KEYCODE_APP_SWITCH,
                0,
                0,
                KeyCharacterMap.VIRTUAL_KEYBOARD,
                0,
                0,
                InputDevice.SOURCE_KEYBOARD);
        try {
            invoke(setDisplayId, event, DEFAULT_DISPLAY_ID);
            Object displayId = invoke(getDisplayId, event);
            if (!Integer.valueOf(DEFAULT_DISPLAY_ID).equals(displayId)) {
                throw new IllegalStateException("app-switch key event display differs");
            }
            Object injected = invoke(
                    injectInputEvent,
                    automation,
                    event,
                    true,
                    false);
            if (!Boolean.TRUE.equals(injected)) {
                throw new IllegalStateException("UiAutomation rejected an app-switch key event");
            }
        } finally {
            event.recycle();
        }
    }

    private static long injectAppSwitchKey(
            UiAutomation automation,
            Method injectInputEvent,
            Method setDisplayId,
            Method getDisplayId) throws Exception {
        long eventTime = SystemClock.uptimeMillis();
        long startedAt = eventTime;
        openPhase("key-down-start");
        injectAppSwitchKeyEvent(
                automation,
                injectInputEvent,
                setDisplayId,
                getDisplayId,
                KeyEvent.ACTION_DOWN,
                eventTime);
        openPhase("key-down-complete");
        openPhase("key-up-start");
        injectAppSwitchKeyEvent(
                automation,
                injectInputEvent,
                setDisplayId,
                getDisplayId,
                KeyEvent.ACTION_UP,
                eventTime);
        openPhase("key-up-complete");
        return SystemClock.uptimeMillis() - startedAt;
    }

    public static void main(String[] arguments) throws Exception {
        boolean openRecents = arguments.length == 1
                && OPEN_RECENTS_ARGUMENT.equals(arguments[0]);
        if (!openRecents && arguments.length != 4) {
            throw new IllegalArgumentException(
                    "expected open-recents-with-app-switch-key or four coordinates");
        }
        int startX = 0;
        int startY = 0;
        int endX = 0;
        int endY = 0;
        if (!openRecents) {
            startX = requiredCoordinate(arguments, 0, "start_x");
            startY = requiredCoordinate(arguments, 1, "start_y");
            endX = requiredCoordinate(arguments, 2, "end_x");
            endY = requiredCoordinate(arguments, 3, "end_y");
            if (startX != endX || startY <= 0 || endY < 0 || endY >= startY) {
                throw new IllegalArgumentException("gesture geometry differs");
            }
        }

        Class<?> wrapperType = Class.forName(UIAUTOMATION_WRAPPER_CLASS);
        Object wrapper = wrapperType.getConstructor().newInstance();
        Method connect = wrapperType.getMethod("connect");
        Method disconnect = wrapperType.getMethod("disconnect");
        Method getUiAutomation = wrapperType.getMethod("getUiAutomation");
        Method injectInputEvent = UiAutomation.class.getMethod(
                "injectInputEvent",
                InputEvent.class,
                boolean.class,
                boolean.class);
        Method setDisplayId = InputEvent.class.getMethod("setDisplayId", int.class);
        Method getDisplayId = InputEvent.class.getMethod("getDisplayId");
        boolean connected = false;
        Exception failure = null;
        long elapsedMillis = 0;
        try {
            invoke(connect, wrapper);
            connected = true;
            Object automationValue = invoke(getUiAutomation, wrapper);
            if (!(automationValue instanceof UiAutomation)) {
                throw new IllegalStateException("UiAutomation wrapper returned a different type");
            }
            UiAutomation automation = (UiAutomation) automationValue;
            if (openRecents) {
                elapsedMillis = injectAppSwitchKey(
                        automation,
                        injectInputEvent,
                        setDisplayId,
                        getDisplayId);
            } else {
                long startedAt = SystemClock.uptimeMillis();
                injectGesture(
                        automation,
                        injectInputEvent,
                        startX,
                        startY,
                        endX,
                        endY);
                elapsedMillis = SystemClock.uptimeMillis() - startedAt;
            }
        } catch (Exception error) {
            failure = error;
        } finally {
            if (connected) {
                try {
                    invoke(disconnect, wrapper);
                } catch (Exception disconnectError) {
                    if (failure != null) {
                        failure.addSuppressed(disconnectError);
                    } else {
                        failure = disconnectError;
                    }
                }
            }
        }

        if (failure != null) {
            failure.printStackTrace(System.err);
            System.err.flush();
            System.exit(1);
            return;
        }

        if (openRecents) {
            System.out.printf(
                    Locale.ROOT,
                    "ANDROID_RECENTS_DIRECT_OPEN=pass action=ui-automation-app-switch-key "
                            + "key=KEYCODE_APP_SWITCH keycode=%d events=%d display_id=%d "
                            + "source=keyboard device=virtual-keyboard "
                            + "wait_for_animations=false elapsed_ms=%d%n",
                    KeyEvent.KEYCODE_APP_SWITCH,
                    OPEN_EVENT_COUNT,
                    DEFAULT_DISPLAY_ID,
                    elapsedMillis);
        } else {
            System.out.printf(
                    Locale.ROOT,
                    "ANDROID_RECENTS_DIRECT_INJECTION=pass events=%d steps=%d step_ms=%d "
                            + "wait_for_animations=false elapsed_ms=%d%n",
                    GESTURE_EVENT_COUNT,
                    GESTURE_STEPS,
                    GESTURE_STEP_MILLIS,
                    elapsedMillis);
        }
        System.out.flush();
        System.exit(0);
    }
}
