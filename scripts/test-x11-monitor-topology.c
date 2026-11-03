/* Controlled two-monitor topology for the isolated capture/viewer fixtures. */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xrandr.h>
#include <X11/extensions/XTest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef MONITOR_FIXTURE_UID
#define MONITOR_FIXTURE_UID 4000
#endif

static const char *names[2] = {"RustDesk-test-left", "RustDesk-test-right"};
static int errors;

static int record_error(Display *display, XErrorEvent *event) {
    (void)display;
    fprintf(stderr, "monitor fixture X error=%u request=%u minor=%u\n",
            event->error_code, event->request_code, event->minor_code);
    errors++;
    return 0;
}

static int pair_matches(Display *display, Window root) {
    int count = 0, matched = 0;
    XRRMonitorInfo *monitors = XRRGetMonitors(display, root, True, &count);
    if (monitors == NULL) return 0;
    for (int i = 0; i < count; ++i) {
        for (int side = 0; side < 2; ++side) {
            if (monitors[i].name == XInternAtom(display, names[side], True) &&
                monitors[i].x == side * 640 && monitors[i].y == 0 &&
                monitors[i].width == 640 && monitors[i].height == 480 &&
                monitors[i].primary == (side == 0) && !monitors[i].automatic) {
                matched |= 1 << side;
            }
        }
    }
    XRRFreeMonitors(monitors);
    return count == 2 && matched == 3 && errors == 0;
}

static int automatic_matches(Display *display, Window root, RROutput *output) {
    int count = 0;
    XRRMonitorInfo *monitors = XRRGetMonitors(display, root, True, &count);
    int valid = monitors != NULL && count == 1 && monitors[0].automatic &&
                monitors[0].noutput == 1 && monitors[0].x == 0 &&
                monitors[0].y == 0 && monitors[0].width == 1280 &&
                monitors[0].height == 480;
    if (valid && output != NULL) *output = monitors[0].outputs[0];
    if (monitors != NULL) XRRFreeMonitors(monitors);
    return valid && errors == 0;
}

int main(int argc, char **argv) {
    if (getuid() != MONITOR_FIXTURE_UID || getgid() != MONITOR_FIXTURE_UID || geteuid() != getuid() ||
        getegid() != getgid() || getenv("DISPLAY") == NULL ||
        strcmp(getenv("DISPLAY"), ":98") != 0 || argc != 2 ||
        (strcmp(argv[1], "prepare") != 0 && strcmp(argv[1], "retire") != 0)) {
        return 2;
    }
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) return 1;
    XSetErrorHandler(record_error);
    Window root = DefaultRootWindow(display);
    int status = 1, major = 1, minor = 5;
    if (ScreenCount(display) != 1 || DisplayWidth(display, 0) != 1280 ||
        DisplayHeight(display, 0) != 480 ||
        !XRRQueryVersion(display, &major, &minor) ||
        major < 1 || (major == 1 && minor < 5)) goto out;
    if (strcmp(argv[1], "retire") == 0) {
        if (!pair_matches(display, root)) goto out;
        for (int side = 0; side < 2; ++side) {
            XRRDeleteMonitor(display, root, XInternAtom(display, names[side], True));
        }
        XSync(display, False);
        if (!automatic_matches(display, root, NULL)) goto out;
        puts("X11_MONITOR_TOPOLOGY_RETIRED=pass monitors=automatic-single");
        status = 0;
        goto out;
    }
    RROutput output = None;
    if (!automatic_matches(display, root, &output)) goto out;
    for (int side = 0; side < 2; ++side) {
        XRRMonitorInfo *monitor = XRRAllocateMonitor(display, side == 0 ? 1 : 0);
        if (monitor == NULL) goto out;
        monitor->name = XInternAtom(display, names[side], False);
        monitor->primary = side == 0;
        monitor->automatic = False;
        monitor->noutput = side == 0 ? 1 : 0;
        monitor->x = side * 640;
        monitor->y = 0;
        monitor->width = 640;
        monitor->height = 480;
        monitor->mwidth = 169;
        monitor->mheight = 127;
        if (side == 0) monitor->outputs[0] = output;
        XRRSetMonitor(display, root, monitor);
        XRRFreeMonitors(monitor);
    }
    XSync(display, False);
    if (!pair_matches(display, root)) goto out;
    Visual *visual = DefaultVisual(display, 0);
    if (visual->red_mask != 0xff0000 || visual->green_mask != 0xff00 ||
        visual->blue_mask != 0xff) goto out;
    GC gc = XCreateGC(display, root, 0, NULL);
    if (gc == NULL) goto out;
    for (int side = 0; side < 2; ++side) {
        XSetForeground(display, gc, side == 0 ? 0xff0000 : 0x0000ff);
        XFillRectangle(display, root, gc, side * 640, 0, 640, 480);
    }
    XFreeGC(display, gc);
    XSync(display, False);
    for (int step = 0; step < 3; ++step) {
        int side = step == 1, x = side * 640 + 317, y = 239;
        Window observed_root, child;
        int root_x, root_y, window_x, window_y;
        unsigned int mask;
        if (!XTestFakeMotionEvent(display, 0, x, y, CurrentTime)) goto out;
        XSync(display, False);
        if (!XQueryPointer(display, root, &observed_root, &child, &root_x, &root_y,
                           &window_x, &window_y, &mask) || observed_root != root ||
            root_x != x || root_y != y) goto out;
        XImage *pixel = XGetImage(display, root, x, y, 1, 1, AllPlanes, ZPixmap);
        if (pixel == NULL) goto out;
        unsigned long color = XGetPixel(pixel, 0, 0);
        XDestroyImage(pixel);
        if (color != (side == 0 ? 0xff0000UL : 0x0000ffUL)) goto out;
    }
    if (errors != 0) goto out;
    puts("X11_MONITOR_TOPOLOGY_READY=pass monitors=2 root=1280x480 geometry=640x480+0+0,640x480+640+0 pixels=red,blue pointer=left-right-left");
    status = 0;
out:
    XCloseDisplay(display);
    return errors == 0 ? status : 1;
}
