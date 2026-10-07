/* Native client-header oracle. This executes only in the disposable X11 fixture. */
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <stddef.h>

static unsigned errors;
static unsigned last_error;
static unsigned bad_device_errors;
static XErrorHandler previous_handler;

static int record_error(Display *display, XErrorEvent *event)
{
    (void)display;
    errors++;
    last_error = event->error_code;
    if (((event->resourceid >> 24) & 0xff) == XkbErr_BadDevice
        && (event->resourceid & 0xff) == 255)
        bad_device_errors++;
    return 0;
}

size_t input_state_layout(unsigned index)
{
    const size_t values[] = {
        sizeof(XkbStateRec), _Alignof(XkbStateRec),
        offsetof(XkbStateRec, group), offsetof(XkbStateRec, base_group),
        offsetof(XkbStateRec, latched_group), offsetof(XkbStateRec, locked_group),
        offsetof(XkbStateRec, mods), offsetof(XkbStateRec, base_mods),
        offsetof(XkbStateRec, latched_mods), offsetof(XkbStateRec, locked_mods),
        offsetof(XkbStateRec, compat_state), offsetof(XkbStateRec, grab_mods),
        offsetof(XkbStateRec, compat_grab_mods), offsetof(XkbStateRec, lookup_mods),
        offsetof(XkbStateRec, compat_lookup_mods), offsetof(XkbStateRec, ptr_buttons),
    };
    return index < sizeof(values) / sizeof(values[0]) ? values[index] : (size_t)-1;
}

int input_native_state(void *display, unsigned device, void *buffer)
{
    return XkbGetState(display, device, buffer);
}

int input_keyboard_error(void *display)
{
    int opcode, event, error;
    int major = XkbMajorVersion, minor = XkbMinorVersion;
    if (!XkbQueryExtension(display, &opcode, &event, &error, &major, &minor))
        return -1;
    return error + XkbKeyboard;
}

void input_install_error_handler(void)
{
    errors = 0;
    last_error = 0;
    bad_device_errors = 0;
    previous_handler = XSetErrorHandler(record_error);
}

unsigned input_error_count(void) { return errors; }
unsigned input_last_error(void) { return last_error; }
unsigned input_bad_device_errors(void) { return bad_device_errors; }
void input_restore_error_handler(void) { XSetErrorHandler(previous_handler); }
