package com.rustdesk.harness;

import android.os.Bundle;
import com.android.uiautomator.core.UiDevice;
import com.android.uiautomator.testrunner.UiAutomatorTestCase;

public final class AndroidRecentsDismiss extends UiAutomatorTestCase {
    private static final int GESTURE_STEPS = 10;

    private static int requiredCoordinate(Bundle parameters, String name) {
        String value = parameters.getString(name);
        if (value == null || !value.matches("[0-9]+")) {
            throw new IllegalArgumentException("missing or malformed coordinate: " + name);
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("coordinate exceeds the integer range: " + name, error);
        }
    }

    public void testDismissBoundTask() {
        Bundle parameters = getParams();
        int startX = requiredCoordinate(parameters, "start_x");
        int startY = requiredCoordinate(parameters, "start_y");
        int endX = requiredCoordinate(parameters, "end_x");
        int endY = requiredCoordinate(parameters, "end_y");
        UiDevice device = getUiDevice();
        int displayWidth = device.getDisplayWidth();
        int displayHeight = device.getDisplayHeight();

        assertTrue("display width is unavailable", displayWidth > 0);
        assertTrue("display height is unavailable", displayHeight > 0);
        assertTrue("start x is outside the display", startX >= 0 && startX < displayWidth);
        assertTrue("end x is outside the display", endX >= 0 && endX < displayWidth);
        assertTrue("start y is outside the display", startY > 0 && startY < displayHeight);
        assertTrue("end y is outside the display", endY >= 0 && endY < startY);

        device.waitForIdle();
        assertTrue(
                "UiAutomator did not observe the Recents swipe",
                device.swipe(startX, startY, endX, endY, GESTURE_STEPS));
        device.waitForIdle();
    }
}
