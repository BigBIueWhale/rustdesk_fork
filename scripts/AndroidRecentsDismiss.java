package com.rustdesk.harness;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.UiAutomation;
import android.graphics.Rect;
import android.os.SystemClock;
import android.view.InputDevice;
import android.view.InputEvent;
import android.view.MotionEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Locale;

public final class AndroidRecentsDismiss {
    private static final int GESTURE_STEPS = 10;
    private static final int GESTURE_STEP_MILLIS = 16;
    private static final int GESTURE_EVENT_COUNT = GESTURE_STEPS + 2;
    private static final String UIAUTOMATION_WRAPPER_CLASS =
            "com.android.uiautomator.core.UiAutomationShellWrapper";
    private static final String OPEN_RECENTS_ARGUMENT = "click-recents-button";
    private static final String RECENTS_BUTTON_VIEW_ID =
            "com.android.systemui:id/recent_apps";

    private AndroidRecentsDismiss() {
    }

    private static void openPhase(String phase) {
        System.out.printf(Locale.ROOT, "ANDROID_RECENTS_OPEN_PHASE=%s%n", phase);
        System.out.flush();
    }

    private static void openPhase(String phase, String detailFormat, Object... details) {
        System.out.printf(
                Locale.ROOT,
                "ANDROID_RECENTS_OPEN_PHASE=%s " + detailFormat + "%n",
                prepend(phase, details));
        System.out.flush();
    }

    private static Object[] prepend(Object first, Object[] remaining) {
        Object[] combined = new Object[remaining.length + 1];
        combined[0] = first;
        System.arraycopy(remaining, 0, combined, 1, remaining.length);
        return combined;
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

    private static void enableInteractiveWindows(UiAutomation automation) {
        AccessibilityServiceInfo serviceInfo = automation.getServiceInfo();
        if (serviceInfo == null) {
            throw new IllegalStateException("UiAutomation service info is unavailable");
        }
        serviceInfo.flags |= AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
                | AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
        automation.setServiceInfo(serviceInfo);
        AccessibilityServiceInfo effectiveInfo = automation.getServiceInfo();
        if (effectiveInfo == null
                || (effectiveInfo.flags
                & AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS) == 0
                || (effectiveInfo.flags
                & AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS) == 0) {
            throw new IllegalStateException(
                    "interactive-window or view-ID retrieval was not enabled");
        }
    }

    private static Rect findUniqueRecentsButton(UiAutomation automation) {
        openPhase("windows-query-start");
        List<AccessibilityWindowInfo> windows = automation.getWindows();
        openPhase("windows-query-complete", "windows=%d", windows.size());
        Rect targetBounds = null;
        int matches = 0;
        int windowIndex = 0;
        try {
            for (AccessibilityWindowInfo window : windows) {
                openPhase(
                        "window-root-start",
                        "index=%d type=%d layer=%d active=%s focused=%s",
                        windowIndex,
                        window.getType(),
                        window.getLayer(),
                        window.isActive(),
                        window.isFocused());
                AccessibilityNodeInfo root = window.getRoot();
                if (root == null) {
                    openPhase("window-root-null", "index=%d", windowIndex);
                    windowIndex++;
                    continue;
                }
                try {
                    openPhase("window-query-start", "index=%d", windowIndex);
                    List<AccessibilityNodeInfo> nodes =
                            root.findAccessibilityNodeInfosByViewId(RECENTS_BUTTON_VIEW_ID);
                    openPhase(
                            "window-query-complete",
                            "index=%d matches=%d",
                            windowIndex,
                            nodes.size());
                    for (AccessibilityNodeInfo node : nodes) {
                        try {
                            matches++;
                            if (!node.isVisibleToUser()
                                    || !node.isEnabled()
                                    || !node.isClickable()) {
                                throw new IllegalStateException(
                                        "SystemUI Recents button is not actionable");
                            }
                            Rect bounds = new Rect();
                            node.getBoundsInScreen(bounds);
                            if (bounds.isEmpty()) {
                                throw new IllegalStateException(
                                        "SystemUI Recents button bounds are empty");
                            }
                            if (targetBounds == null) {
                                targetBounds = bounds;
                            }
                        } finally {
                            node.recycle();
                        }
                    }
                } finally {
                    root.recycle();
                }
                windowIndex++;
            }
        } finally {
            for (AccessibilityWindowInfo window : windows) {
                window.recycle();
            }
        }
        if (matches != 1 || targetBounds == null) {
            throw new IllegalStateException(
                    "expected exactly one SystemUI Recents button, found " + matches);
        }
        return targetBounds;
    }

    private static void injectClick(
            UiAutomation automation,
            Method injectInputEvent,
            int x,
            int y) throws Exception {
        long eventTime = SystemClock.uptimeMillis();
        injectPointer(
                automation,
                injectInputEvent,
                eventTime,
                eventTime,
                MotionEvent.ACTION_DOWN,
                x,
                y);
        injectPointer(
                automation,
                injectInputEvent,
                eventTime,
                eventTime,
                MotionEvent.ACTION_UP,
                x,
                y);
    }

    public static void main(String[] arguments) throws Exception {
        boolean openRecents = arguments.length == 1
                && OPEN_RECENTS_ARGUMENT.equals(arguments[0]);
        if (!openRecents && arguments.length != 4) {
            throw new IllegalArgumentException(
                    "expected click-recents-button or four coordinates");
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

        boolean connected = false;
        Exception failure = null;
        long elapsedMillis = 0;
        long lookupElapsedMillis = 0;
        Rect openBounds = null;
        try {
            if (openRecents) {
                openPhase("connect-start");
            }
            invoke(connect, wrapper);
            connected = true;
            if (openRecents) {
                openPhase("connect-complete");
            }
            Object automationValue = invoke(getUiAutomation, wrapper);
            if (!(automationValue instanceof UiAutomation)) {
                throw new IllegalStateException("UiAutomation wrapper returned a different type");
            }
            UiAutomation automation = (UiAutomation) automationValue;
            if (openRecents) {
                openPhase("automation-ready");
                openPhase("service-flags-start");
                enableInteractiveWindows(automation);
                openPhase("service-flags-complete");
                long lookupStartedAt = SystemClock.uptimeMillis();
                openBounds = findUniqueRecentsButton(automation);
                lookupElapsedMillis = SystemClock.uptimeMillis() - lookupStartedAt;
                openPhase("button-query-complete");
                long clickStartedAt = SystemClock.uptimeMillis();
                openPhase("click-start");
                injectClick(
                        automation,
                        injectInputEvent,
                        openBounds.centerX(),
                        openBounds.centerY());
                elapsedMillis = SystemClock.uptimeMillis() - clickStartedAt;
                openPhase("click-complete");
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
            throw error;
        } finally {
            if (connected) {
                try {
                    if (openRecents) {
                        openPhase("disconnect-start");
                    }
                    invoke(disconnect, wrapper);
                    if (openRecents) {
                        openPhase("disconnect-complete");
                    }
                } catch (Exception disconnectError) {
                    if (failure != null) {
                        failure.addSuppressed(disconnectError);
                    } else {
                        throw disconnectError;
                    }
                }
            }
        }

        if (openRecents) {
            System.out.printf(
                    Locale.ROOT,
                    "ANDROID_RECENTS_DIRECT_OPEN=pass resource=%s "
                            + "bounds=%d,%d,%d,%d center=%d,%d "
                            + "action=ui-automation-physical-click matches=1 events=2 "
                            + "wait_for_animations=false lookup_elapsed_ms=%d "
                            + "click_elapsed_ms=%d%n",
                    RECENTS_BUTTON_VIEW_ID,
                    openBounds.left,
                    openBounds.top,
                    openBounds.right,
                    openBounds.bottom,
                    openBounds.centerX(),
                    openBounds.centerY(),
                    lookupElapsedMillis,
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
    }
}
