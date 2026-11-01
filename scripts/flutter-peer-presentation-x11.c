#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * Test-only X11 observer/controller for one exact RustDesk peer session.
 *
 * It types the password into the real Flutter prompt, observes pixels from the real remote window,
 * repeatedly moves focus to a separate X11 window, returns through a real pointer click, replaces
 * the exact controlled-server generation, and requires current decoded presentation throughout.
 */
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>
#include <X11/extensions/XInput2.h>
#include <X11/keysym.h>
#include <atspi/atspi.h>
#include <gtk/gtk.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "x11-frame-oracle.h"

#define WINDOW_WAIT_MS 45000U
#define PASSWORD_PROMPT_WAIT_MS 30000U
#define PASSWORD_INPUT_WAIT_MS 5000U
#define PASSWORD_PROMPT_RETIRE_MS 10000U
#define PASSWORD_PROMPT_SCAN_INTERVAL_MS 100U
#define PASSWORD_PROMPT_RETIRE_STABLE_SCANS 5U
#define PASSWORD_KEY_INTERVAL_MS 30U
#define ACCESSIBLE_NODE_LIMIT 4096U
#define ACCESSIBLE_CHILD_LIMIT 512
#define ACCESSIBLE_DEPTH_LIMIT 64U
#define ACCESSIBLE_NAME_LIMIT 96U
#define ACCESSIBLE_ACTION_LIMIT 32
#define AUTH_WAIT_MS 30000U
#define RECOVERY_LIMIT_MS 2500U
#define RECONNECT_LIMIT_MS 45000U
#define SAMPLE_INTERVAL_MS 40U
#define FRESH_LIMIT_MS 1000U
#define FOCUS_CYCLE_COUNT 3U
#define RECONNECT_COUNT 3U
#define RESOURCE_THREAD_GROWTH_LIMIT 8U
#define RESOURCE_FD_GROWTH_LIMIT 16U
#define RESOURCE_RSS_GROWTH_KIB_LIMIT 131072ULL
#define DIALOG_CONTROL_WAIT_MS 5000U
#define DIALOG_STABLE_SCANS 5U

static const unsigned int blur_hold_ms[FOCUS_CYCLE_COUNT] = {2000U, 6000U, 12000U};

static const char test_password[] = "rustdesk-peer-9f2a7c4e";
_Static_assert(sizeof(test_password) - 1U == 22U, "test password length must remain exact");

typedef struct {
    Window window;
    unsigned int width;
    unsigned int height;
    unsigned long pid;
    char title[512];
    char instance_name[256];
    char class_name[256];
} ViewerWindow;

typedef struct {
    char local[32];
    char remote[32];
    unsigned long inode;
} ConnectionIdentity;

typedef struct {
    unsigned long long rss_kib;
    unsigned int threads;
    unsigned int descriptors;
} ProcessResources;

typedef struct {
    unsigned int nodes;
    uint64_t diagnostic_deadline;
    unsigned int application_roots;
    unsigned int password_nodes;
    unsigned int visible_passwords;
    unsigned int ready_passwords;
    unsigned int focused_nodes;
    AtspiRole first_focused_role;
    int first_password_editable;
    int first_password_enabled;
    int first_password_sensitive;
    int first_password_visible;
    int first_password_focusable;
    int first_password_focused;
    gint first_password_character_count;
} PasswordPromptScan;

typedef struct {
    const char *name;
    unsigned int nodes;
    unsigned int matches;
    unsigned int dialog_scopes;
    int dialog_caption;
    int text_content;
    uint64_t deadline;
    AtspiAccessible *match;
} NamedControlScan;

static int sleep_millis(unsigned int millis) {
    struct timespec delay = {
        .tv_sec = (time_t)(millis / 1000U),
        .tv_nsec = (long)(millis % 1000U) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static uint64_t monotonic_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static int atspi_process_id(AtspiAccessible *accessible, unsigned int *pid) {
    GError *error = NULL;
    guint value = atspi_accessible_get_process_id(accessible, &error);
    if (error != NULL) {
        g_error_free(error);
        return -1;
    }
    *pid = value;
    return 0;
}

static void print_sanitized_accessible_string(const char *field, const char *name) {
    size_t index;
    size_t length;

    fprintf(stderr, " %s=\"", field);
    if (name == NULL) {
        fputs("<null>", stderr);
    } else {
        length = strnlen(name, ACCESSIBLE_NAME_LIMIT + 1U);
        for (index = 0U; index < length && index < ACCESSIBLE_NAME_LIMIT; ++index) {
            unsigned char value = (unsigned char)name[index];
            fputc(value >= 32U && value <= 126U && value != '"' && value != '\\' ? value : '?',
                  stderr);
        }
        if (length > ACCESSIBLE_NAME_LIMIT) {
            fputs("...", stderr);
        }
    }
    fputs("\"\n", stderr);
}

static int scan_password_prompt_node(AtspiAccessible *accessible, unsigned int expected_pid,
                                     unsigned int depth, PasswordPromptScan *scan,
                                     int emit_diagnostic) {
    GError *error = NULL;
    AtspiStateSet *states;
    AtspiRole role;
    gint child_count;
    gint index;
    unsigned int pid;
    int visible_password;
    int focused;
    int editable;
    int enabled;
    int sensitive;
    int visible;
    int focusable;

    if (depth > ACCESSIBLE_DEPTH_LIMIT || scan->nodes >= ACCESSIBLE_NODE_LIMIT ||
        (emit_diagnostic != 0 && monotonic_millis() >= scan->diagnostic_deadline) ||
        atspi_process_id(accessible, &pid) != 0 || pid != expected_pid) {
        return -1;
    }
    scan->nodes += 1U;
    role = atspi_accessible_get_role(accessible, &error);
    if (error != NULL) {
        g_error_free(error);
        return -1;
    }
    states = atspi_accessible_get_state_set(accessible);
    if (states == NULL) {
        return -1;
    }
    focused = atspi_state_set_contains(states, ATSPI_STATE_FOCUSED);
    if (focused != 0) {
        scan->focused_nodes += 1U;
        if (scan->focused_nodes == 1U) {
            scan->first_focused_role = role;
        }
    }
    editable = atspi_state_set_contains(states, ATSPI_STATE_EDITABLE);
    enabled = atspi_state_set_contains(states, ATSPI_STATE_ENABLED);
    sensitive = atspi_state_set_contains(states, ATSPI_STATE_SENSITIVE);
    visible = atspi_state_set_contains(states, ATSPI_STATE_VISIBLE);
    focusable = atspi_state_set_contains(states, ATSPI_STATE_FOCUSABLE);
    if (role == ATSPI_ROLE_PASSWORD_TEXT) {
        AtspiText *text = atspi_accessible_get_text_iface(accessible);
        gint character_count;
        if (text == NULL) {
            g_object_unref(states);
            return -1;
        }
        character_count = atspi_text_get_character_count(text, &error);
        g_object_unref(text);
        if (error != NULL || character_count < 0) {
            if (error != NULL) {
                g_error_free(error);
            }
            g_object_unref(states);
            return -1;
        }
        if (scan->password_nodes == 0U) {
            scan->first_password_editable = editable;
            scan->first_password_enabled = enabled;
            scan->first_password_sensitive = sensitive;
            scan->first_password_visible = visible;
            scan->first_password_focusable = focusable;
            scan->first_password_focused = focused;
            scan->first_password_character_count = character_count;
        }
        scan->password_nodes += 1U;
    }
    visible_password = role == ATSPI_ROLE_PASSWORD_TEXT &&
                       editable != 0 && enabled != 0 && sensitive != 0 && visible != 0;
    if (visible_password != 0) {
        scan->visible_passwords += 1U;
        if (focused != 0 && focusable != 0) {
            scan->ready_passwords += 1U;
        }
    }
    if (emit_diagnostic != 0) {
        gchar *name = atspi_accessible_get_name(accessible, &error);
        if (error != NULL) {
            g_error_free(error);
            g_object_unref(states);
            return -1;
        }
        fprintf(stderr,
                "FLUTTER_PEER_ATSPI_NODE depth=%u role=%d "
                "editable=%d enabled=%d sensitive=%d visible=%d showing=%d "
                "focusable=%d focused=%d",
                depth, (int)role, editable, enabled, sensitive, visible,
                atspi_state_set_contains(states, ATSPI_STATE_SHOWING), focusable, focused);
        print_sanitized_accessible_string("name", name);
        g_free(name);
        {
            gchar *description = atspi_accessible_get_description(accessible, &error);
            AtspiAction *action = atspi_accessible_get_action_iface(accessible);
            int action_interface = action != NULL;
            gint actions = -1;
            if (error == NULL && action != NULL) {
                actions = atspi_action_get_n_actions(action, &error);
            }
            if (action != NULL) g_object_unref(action);
            if (error != NULL) {
                g_error_free(error);
                g_free(description);
                g_object_unref(states);
                return -1;
            }
            fprintf(stderr, "FLUTTER_PEER_ATSPI_PROPERTIES node=%u depth=%u role=%d "
                    "action_interface=%d actions=%d", scan->nodes, depth, (int)role,
                    action_interface, actions);
            print_sanitized_accessible_string("description", description);
            g_free(description);
        }
    }
    g_object_unref(states);

    child_count = atspi_accessible_get_child_count(accessible, &error);
    if (error != NULL) {
        g_error_free(error);
        return -1;
    }
    if (child_count < 0 || child_count > ACCESSIBLE_CHILD_LIMIT) {
        return -1;
    }
    for (index = 0; index < child_count; ++index) {
        AtspiAccessible *child = atspi_accessible_get_child_at_index(accessible, index, &error);
        int status;
        if (error != NULL || child == NULL) {
            if (error != NULL) {
                g_error_free(error);
            }
            return -1;
        }
        status =
            scan_password_prompt_node(child, expected_pid, depth + 1U, scan, emit_diagnostic);
        g_object_unref(child);
        if (status != 0) {
            return -1;
        }
    }
    return 0;
}

static int scan_password_prompt(unsigned int expected_pid, PasswordPromptScan *scan,
                                int emit_diagnostic) {
    AtspiAccessible *desktop;
    GError *error = NULL;
    gint child_count;
    gint index;
    gint desktop_count;

    memset(scan, 0, sizeof(*scan));
    if (emit_diagnostic != 0) {
        scan->diagnostic_deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
        fprintf(stderr, "FLUTTER_PEER_ATSPI_ROLE_VALUES image=%d menu=%d menu_item=%d "
                "diagnostic_budget_ms=%u\n", (int)ATSPI_ROLE_IMAGE,
                (int)ATSPI_ROLE_MENU, (int)ATSPI_ROLE_MENU_ITEM,
                DIALOG_CONTROL_WAIT_MS);
    }
    scan->first_focused_role = ATSPI_ROLE_INVALID;
    scan->first_password_character_count = -1;
    desktop_count = atspi_get_desktop_count();
    if (desktop_count != 1) {
        if (emit_diagnostic != 0) {
            fprintf(stderr, "FLUTTER_PEER_ATSPI_SCAN_FAIL stage=desktop-count count=%d\n",
                    desktop_count);
        }
        return -1;
    }
    desktop = atspi_get_desktop(0);
    if (desktop == NULL) {
        if (emit_diagnostic != 0) {
            fputs("FLUTTER_PEER_ATSPI_SCAN_FAIL stage=desktop-object\n", stderr);
        }
        return -1;
    }
    atspi_accessible_clear_cache(desktop);
    child_count = atspi_accessible_get_child_count(desktop, &error);
    if (error != NULL) {
        if (emit_diagnostic != 0) {
            fprintf(stderr, "FLUTTER_PEER_ATSPI_SCAN_FAIL stage=desktop-children error_code=%d\n",
                    error->code);
        }
        g_error_free(error);
        g_object_unref(desktop);
        return -1;
    }
    if (child_count < 0 || child_count > ACCESSIBLE_CHILD_LIMIT) {
        if (emit_diagnostic != 0) {
            fprintf(stderr, "FLUTTER_PEER_ATSPI_SCAN_FAIL stage=desktop-child-bound children=%d\n",
                    child_count);
        }
        g_object_unref(desktop);
        return -1;
    }
    for (index = 0; index < child_count; ++index) {
        AtspiAccessible *application =
            atspi_accessible_get_child_at_index(desktop, index, &error);
        unsigned int pid;
        int status;
        if (error != NULL || application == NULL) {
            if (error != NULL) {
                g_error_free(error);
            }
            g_object_unref(desktop);
            return -1;
        }
        status = atspi_process_id(application, &pid);
        if (status == 0 && pid == expected_pid) {
            scan->application_roots += 1U;
            status = scan_password_prompt_node(application, expected_pid, 0U, scan,
                                               emit_diagnostic);
        }
        g_object_unref(application);
        if (status != 0) {
            if (emit_diagnostic != 0) {
                fprintf(stderr, "FLUTTER_PEER_ATSPI_SCAN_FAIL stage=application-scan "
                        "index=%d applications=%u nodes=%u\n",
                        index, scan->application_roots, scan->nodes);
            }
            g_object_unref(desktop);
            return -1;
        }
    }
    g_object_unref(desktop);
    if (emit_diagnostic != 0 && scan->application_roots == 0U) {
        fprintf(stderr, "FLUTTER_PEER_ATSPI_SCAN_FAIL stage=application-count "
                "applications=0 desktop_children=%d\n", child_count);
    }
    return scan->application_roots > 0U ? 0 : -1;
}

static int wait_for_password_prompt(unsigned int expected_pid, PasswordPromptScan *last_scan) {
    uint64_t deadline = monotonic_millis() + PASSWORD_PROMPT_WAIT_MS;
    memset(last_scan, 0, sizeof(*last_scan));
    last_scan->first_focused_role = ATSPI_ROLE_INVALID;
    last_scan->first_password_character_count = -1;
    while (monotonic_millis() < deadline) {
        PasswordPromptScan scan;
        if (scan_password_prompt(expected_pid, &scan, 0) == 0) {
            *last_scan = scan;
            if (scan.password_nodes == 1U && scan.visible_passwords == 1U &&
                scan.ready_passwords == 1U && scan.first_password_character_count == 0) {
                return 0;
            }
            if (scan.password_nodes > 1U || scan.visible_passwords > 1U ||
                scan.ready_passwords > 1U) {
                return -1;
            }
        }
        if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static int wait_for_password_character_count(unsigned int expected_pid, gint expected_count,
                                             PasswordPromptScan *last_scan) {
    uint64_t deadline = monotonic_millis() + PASSWORD_INPUT_WAIT_MS;
    while (monotonic_millis() < deadline) {
        PasswordPromptScan scan;
        if (scan_password_prompt(expected_pid, &scan, 0) == 0) {
            *last_scan = scan;
            if (scan.password_nodes == 1U && scan.visible_passwords == 1U &&
                scan.ready_passwords == 1U &&
                scan.first_password_character_count == expected_count) {
                return 0;
            }
            if (scan.password_nodes > 1U || scan.visible_passwords > 1U ||
                scan.ready_passwords > 1U ||
                scan.first_password_character_count > expected_count) {
                return -1;
            }
        }
        if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static int wait_for_password_prompt_retirement(unsigned int expected_pid,
                                               PasswordPromptScan *last_scan) {
    uint64_t deadline = monotonic_millis() + PASSWORD_PROMPT_RETIRE_MS;
    unsigned int stable_scans = 0U;
    while (monotonic_millis() < deadline) {
        PasswordPromptScan scan;
        if (scan_password_prompt(expected_pid, &scan, 0) == 0) {
            *last_scan = scan;
            if (scan.password_nodes == 0U) {
                stable_scans += 1U;
                if (stable_scans >= PASSWORD_PROMPT_RETIRE_STABLE_SCANS) {
                    return 0;
                }
            } else {
                stable_scans = 0U;
            }
        } else {
            stable_scans = 0U;
        }
        if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static void exit_atspi_after_failure(void) {
    if (atspi_exit() != 0) {
        fputs("FLUTTER_PEER_X11_FAIL private AT-SPI teardown after primary failure\n", stderr);
    }
}

static int named_control_refusal(const NamedControlScan *scan, const char *reason,
                                  unsigned int depth, GError *error) {
    fprintf(stderr, "FLUTTER_PEER_CONTROL_QUERY_FAIL control=\"%s\" reason=%s "
            "depth=%u nodes=%u matches=%u error_code=%d\n",
            scan->name, reason, depth, scan->nodes, scan->matches,
            error != NULL ? error->code : 0);
    if (error != NULL) g_error_free(error);
    return -1;
}

static int scan_named_control_node(AtspiAccessible *accessible, unsigned int expected_pid,
                                    unsigned int depth, NamedControlScan *scan, int dialog_scope) {
    GError *error = NULL;
    unsigned int pid;
    AtspiStateSet *states;
    gchar *name;
    gint children;
    if (depth > ACCESSIBLE_DEPTH_LIMIT) {
        return named_control_refusal(scan, "depth-bound", depth, NULL);
    }
    if (scan->nodes >= ACCESSIBLE_NODE_LIMIT) {
        return named_control_refusal(scan, "node-bound", depth, NULL);
    }
    if (monotonic_millis() >= scan->deadline) {
        return named_control_refusal(scan, "deadline", depth, NULL);
    }
    pid = atspi_accessible_get_process_id(accessible, &error);
    if (error != NULL || pid != expected_pid) {
        return named_control_refusal(scan, error != NULL ? "peer-query" : "foreign-peer",
                                     depth, error);
    }
    scan->nodes += 1U;
    atspi_accessible_clear_cache(accessible);
    states = atspi_accessible_get_state_set(accessible);
    if (states == NULL) {
        return named_control_refusal(scan, "states-unavailable", depth, NULL);
    }
    if (atspi_state_set_contains(states, ATSPI_STATE_VISIBLE) &&
        atspi_state_set_contains(states, ATSPI_STATE_SHOWING)) {
        name = atspi_accessible_get_name(accessible, &error);
        if (error != NULL) {
            g_object_unref(states);
            return named_control_refusal(scan, "name-query", depth, error);
        }
        if (name != NULL && strnlen(name, ACCESSIBLE_NAME_LIMIT + 1U) <= ACCESSIBLE_NAME_LIMIT) {
            if (scan->dialog_caption != 0 && strcmp(name, "Alert") == 0) {
                scan->dialog_scopes += 1U;
                dialog_scope = 1;
            }
            if (scan->text_content == 0 && strcmp(name, scan->name) == 0 &&
                (scan->dialog_caption == 0 || dialog_scope != 0)) {
                scan->matches += 1U;
                if (scan->match == NULL) {
                    scan->match = g_object_ref(accessible);
                }
            }
        }
        g_free(name);
        if (scan->text_content != 0 && dialog_scope != 0) {
            AtspiText *text = atspi_accessible_get_text_iface(accessible);
            if (text != NULL) {
                gint count = atspi_text_get_character_count(text, &error);
                gchar *content = NULL;
                if (error == NULL && count >= 0 && count <= (gint)ACCESSIBLE_NAME_LIMIT)
                    content = atspi_text_get_text(text, 0, count, &error);
                if (error == NULL && content != NULL && strcmp(content, scan->name) == 0) {
                    scan->matches += 1U;
                    if (scan->match == NULL) scan->match = g_object_ref(accessible);
                }
                g_free(content);
                g_object_unref(text);
                if (error != NULL || count < 0) {
                    g_object_unref(states);
                    return named_control_refusal(scan, "text-query", depth, error);
                }
            }
        }
    }
    g_object_unref(states);
    if (scan->dialog_scopes > 1U) {
        return named_control_refusal(scan, "duplicate-dialog-scope", depth, NULL);
    }
    if (scan->matches > 1U || monotonic_millis() >= scan->deadline) {
        return named_control_refusal(scan, scan->matches > 1U ? "duplicate-name" : "deadline",
                                     depth, NULL);
    }
    children = atspi_accessible_get_child_count(accessible, &error);
    if (error != NULL || children < 0 || children > ACCESSIBLE_CHILD_LIMIT) {
        return named_control_refusal(scan, error != NULL ? "children-query" : "children-bound",
                                     depth, error);
    }
    for (gint index = 0; index < children; ++index) {
        AtspiAccessible *child = atspi_accessible_get_child_at_index(accessible, index, &error);
        int status;
        if (error != NULL || child == NULL) {
            if (child != NULL) g_object_unref(child);
            return named_control_refusal(scan, "child-query", depth, error);
        }
        status = scan_named_control_node(child, expected_pid, depth + 1U, scan, dialog_scope);
        g_object_unref(child);
        if (status != 0) return -1;
    }
    return 0;
}

static int query_accessible(unsigned int expected_pid, const char *name, uint64_t deadline,
                              AtspiAccessible **match, int dialog_caption, int text_content) {
    NamedControlScan scan = {.name = name, .deadline = deadline, .dialog_caption = dialog_caption,
                            .text_content = text_content};
    AtspiAccessible *desktop;
    GError *error = NULL;
    gint children;
    unsigned int applications = 0U;
    int status = -1;
    const char *reason = "desktop-unavailable";
    *match = NULL;
    if (atspi_get_desktop_count() != 1 || (desktop = atspi_get_desktop(0)) == NULL) {
        return named_control_refusal(&scan, reason, 0U, NULL);
    }
    atspi_accessible_clear_cache(desktop);
    reason = "desktop-children-query";
    children = atspi_accessible_get_child_count(desktop, &error);
    if (error != NULL || children < 0 || children > ACCESSIBLE_CHILD_LIMIT) goto out;
    for (gint index = 0; index < children; ++index) {
        reason = "application-child-query";
        AtspiAccessible *application = atspi_accessible_get_child_at_index(desktop, index, &error);
        unsigned int pid;
        int application_status;
        if (error != NULL || application == NULL) {
            if (application != NULL) g_object_unref(application);
            goto out;
        }
        reason = "application-peer-query";
        application_status = atspi_process_id(application, &pid);
        if (application_status == 0 && pid == expected_pid) {
            applications += 1U;
            reason = "application-scan";
            application_status = scan_named_control_node(application, expected_pid, 0U, &scan, 0);
        }
        g_object_unref(application);
        if (application_status != 0) goto out;
    }
    reason = applications != 1U ? "application-count" : "deadline";
    if (applications == 1U && monotonic_millis() < deadline) {
        *match = scan.match;
        scan.match = NULL;
        status = 0;
    }
out:
    if (status != 0) {
        fprintf(stderr, "FLUTTER_PEER_CONTROL_QUERY_SUMMARY control=\"%s\" reason=%s "
                "applications=%u nodes=%u matches=%u error_code=%d\n",
                name, reason, applications, scan.nodes, scan.matches,
                error != NULL ? error->code : 0);
    }
    if (error != NULL) g_error_free(error);
    if (scan.match != NULL) g_object_unref(scan.match);
    g_object_unref(desktop);
    return status;
}

static int query_named_accessible(unsigned int expected_pid, const char *name, uint64_t deadline,
                                   AtspiAccessible **match, int dialog_caption) {
    return query_accessible(expected_pid, name, deadline, match, dialog_caption, 0);
}

static int query_dialog_caption(unsigned int expected_pid, uint64_t deadline,
                                 AtspiAccessible **match) {
    return query_named_accessible(expected_pid, "Trackpad speed", deadline, match, 1);
}

static int activate_named_control(unsigned int expected_pid, const char *name) {
    uint64_t started = monotonic_millis();
    uint64_t deadline = started + DIALOG_CONTROL_WAIT_MS;
    unsigned int attempts = 0U;
    while (monotonic_millis() < deadline) {
        AtspiAccessible *control = NULL;
        AtspiAction *action;
        AtspiStateSet *states;
        GError *error = NULL;
        int status = -1;
        int enabled, sensitive;
        gint actions = -1;
        gint action_names = 0;
        gint tap_index = -1;
        unsigned int tap_matches = 0U;
        gboolean invoked = FALSE;
        attempts += 1U;
        if (query_named_accessible(expected_pid, name, deadline, &control, 0) != 0) {
            fprintf(stderr, "FLUTTER_PEER_CONTROL_ACTIVATION control=\"%s\" result=query-refused "
                    "attempts=%u elapsed_ms=%llu\n", name, attempts,
                    (unsigned long long)(monotonic_millis() - started));
            return -1;
        }
        if (control == NULL) {
            if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) return -1;
            continue;
        }
        states = atspi_accessible_get_state_set(control);
        action = atspi_accessible_get_action_iface(control);
        enabled = states != NULL && atspi_state_set_contains(states, ATSPI_STATE_ENABLED);
        sensitive = states != NULL && atspi_state_set_contains(states, ATSPI_STATE_SENSITIVE);
        if (action != NULL && enabled && sensitive) {
            actions = atspi_action_get_n_actions(action, &error);
            if (error == NULL && actions > 0 && actions <= ACCESSIBLE_ACTION_LIMIT) {
                for (gint index = 0; index < actions && monotonic_millis() < deadline; ++index) {
                    gchar *action_name = atspi_action_get_action_name(action, index, &error);
                    if (error != NULL || action_name == NULL ||
                        strnlen(action_name, ACCESSIBLE_NAME_LIMIT + 1U) > ACCESSIBLE_NAME_LIMIT) {
                        g_free(action_name);
                        break;
                    }
                    fprintf(stderr, "FLUTTER_PEER_CONTROL_ACTION control=\"%s\" index=%d",
                            name, index);
                    print_sanitized_accessible_string("name", action_name);
                    action_names += 1;
                    if (strcmp(action_name, "Tap") == 0) {
                        tap_index = index;
                        tap_matches += 1U;
                    }
                    g_free(action_name);
                }
                if (error == NULL && action_names == actions && tap_matches == 1U &&
                    monotonic_millis() < deadline &&
                    atspi_action_get_n_actions(action, &error) == actions && error == NULL) {
                    gchar *action_name = atspi_action_get_action_name(action, tap_index, &error);
                    if (error == NULL && action_name != NULL && strcmp(action_name, "Tap") == 0 &&
                        monotonic_millis() < deadline) {
                        invoked = atspi_action_do_action(action, tap_index, &error);
                        if (invoked && error == NULL && monotonic_millis() < deadline) status = 0;
                    }
                    g_free(action_name);
                }
            }
        }
        fprintf(stderr, "FLUTTER_PEER_CONTROL_ACTIVATION control=\"%s\" result=%s "
                "attempts=%u elapsed_ms=%llu enabled=%d sensitive=%d actions=%d "
                "tap_matches=%u tap_index=%d invoked=%d error_code=%d\n",
                name, status == 0 ? "activated" : "action-refused", attempts,
                (unsigned long long)(monotonic_millis() - started),
                enabled, sensitive, actions, tap_matches, tap_index, invoked,
                error != NULL ? error->code : 0);
        if (error != NULL) g_error_free(error);
        if (action != NULL) g_object_unref(action);
        if (states != NULL) g_object_unref(states);
        g_object_unref(control);
        return status;
    }
    fprintf(stderr, "FLUTTER_PEER_CONTROL_ACTIVATION control=\"%s\" result=not-found "
            "attempts=%u elapsed_ms=%llu\n", name, attempts,
            (unsigned long long)(monotonic_millis() - started));
    return -1;
}

static int require_same_dialog(unsigned int expected_pid, AtspiAccessible *expected) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    for (unsigned int sample = 0U; sample < DIALOG_STABLE_SCANS; ++sample) {
        AtspiAccessible *actual = NULL;
        int status = query_dialog_caption(expected_pid, deadline, &actual);
        int same = actual == expected;
        int present = actual != NULL;
        if (actual != NULL) g_object_unref(actual);
        if (status != 0 || same == 0) {
            fprintf(stderr, "FLUTTER_PEER_X11_FAIL dialog identity observation=%s\n",
                    status != 0 ? "unavailable" : present != 0 ? "replaced" : "absent");
            return -1;
        }
        if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) return -1;
    }
    return monotonic_millis() < deadline ? 0 : -1;
}

static int wait_for_dialog_retirement(unsigned int expected_pid) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    unsigned int absent_scans = 0U;
    while (monotonic_millis() < deadline && absent_scans < DIALOG_STABLE_SCANS) {
        AtspiAccessible *actual = NULL;
        int query_status = query_dialog_caption(expected_pid, deadline, &actual);
        int absent = actual == NULL;
        if (actual != NULL) g_object_unref(actual);
        if (query_status != 0) return -1;
        absent_scans = absent != 0 ? absent_scans + 1U : 0U;
        if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) return -1;
    }
    return absent_scans == DIALOG_STABLE_SCANS && monotonic_millis() < deadline ? 0 : -1;
}

static int open_trackpad_dialog(unsigned int expected_pid, AtspiAccessible **caption) {
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    AtspiAccessible *show = NULL;
    AtspiAccessible *hide = NULL;
    unsigned int attempts = 0U;
    uint64_t started;
    int status = -1;
    *caption = NULL;
    if (query_named_accessible(expected_pid, "Show toolbar", deadline, &show, 0) != 0 ||
        query_named_accessible(expected_pid, "Hide toolbar", deadline, &hide, 0) != 0 ||
        (show == NULL) == (hide == NULL)) {
        fputs("FLUTTER_PEER_X11_FAIL toolbar expansion state unavailable or ambiguous\n", stderr);
        goto out;
    }
    if (show != NULL && activate_named_control(expected_pid, "Show toolbar") != 0) goto out;
    if (activate_named_control(expected_pid, "Keyboard settings") != 0) {
        fputs("FLUTTER_PEER_X11_FAIL actual toolbar disclosure\n", stderr);
        goto out;
    }
    printf("FLUTTER_PEER_TOOLBAR_DISCLOSURE_OK expansion=%s keyboard_settings=activated\n",
           show != NULL ? "actual_tap" : "already_expanded");
    fflush(stdout);
    if (activate_named_control(expected_pid, "Trackpad speed") != 0) {
        fputs("FLUTTER_PEER_X11_FAIL actual toolbar dialog activation\n", stderr);
        goto out;
    }
    started = monotonic_millis();
    deadline = started + DIALOG_CONTROL_WAIT_MS;
    while (monotonic_millis() < deadline && *caption == NULL) {
        attempts += 1U;
        if (query_dialog_caption(expected_pid, deadline, caption) != 0 ||
            sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) goto out;
    }
    fprintf(stderr, "FLUTTER_PEER_DIALOG_CAPTION found=%d scope=Alert attempts=%u elapsed_ms=%llu\n",
            *caption != NULL, attempts, (unsigned long long)(monotonic_millis() - started));
    if (*caption == NULL || require_same_dialog(expected_pid, *caption) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL actual dialog did not become stable\n", stderr);
        goto out;
    }
    status = 0;
out:
    if (show != NULL) g_object_unref(show);
    if (hide != NULL) g_object_unref(hide);
    if (status != 0) g_clear_object(caption);
    return status;
}

static int read_control_position(AtspiAccessible *control, int *x, int *y) {
    AtspiComponent *component = atspi_accessible_get_component_iface(control);
    AtspiRect *rect;
    GError *error = NULL;
    int status = -1;
    if (component == NULL) {
        fputs("FLUTTER_PEER_DIALOG_EXTENTS_FAIL component=unavailable\n", stderr);
        return -1;
    }
    atspi_accessible_clear_cache(control);
    uint64_t started = monotonic_millis();
    rect = atspi_component_get_extents(component, ATSPI_COORD_TYPE_SCREEN, &error);
    uint64_t elapsed = monotonic_millis() - started;
    if (error == NULL && rect != NULL && rect->width > 0 && rect->height > 0) {
        *x = rect->x;
        *y = rect->y;
        status = 0;
    }
    if (status != 0) {
        fprintf(stderr, "FLUTTER_PEER_DIALOG_EXTENTS_FAIL component=present rect=%d "
                "width=%d height=%d elapsed_ms=%llu error_domain=%u error_code=%d", rect != NULL,
                rect != NULL ? rect->width : -1, rect != NULL ? rect->height : -1,
                (unsigned long long)elapsed,
                error != NULL ? error->domain : 0U,
                error != NULL ? error->code : 0);
        print_sanitized_accessible_string("error", error != NULL ? error->message : NULL);
    }
    if (error != NULL) g_error_free(error);
    if (rect != NULL) g_boxed_free(ATSPI_TYPE_RECT, rect);
    g_object_unref(component);
    return status;
}

static int64_t source_state(Display *display) {
    uint8_t pixels[X11_FRAME_BYTES];
    uint64_t captured_us = 0U;
    return x11_frame_capture(display, RootWindow(display, DefaultScreen(display)),
                              pixels, &captured_us);
}

static int64_t viewer_state(Display *display, const ViewerWindow *viewer,
                             uint64_t *captured_us) {
    uint8_t pixels[X11_FRAME_BYTES];
    return x11_frame_capture(display, viewer->window, pixels, captured_us);
}

static int read_text_property(Display *display, Window window, Atom property,
                              char *destination, size_t destination_size) {
    Atom actual_type = None;
    int actual_format = 0;
    unsigned long item_count = 0UL;
    unsigned long bytes_after = 0UL;
    unsigned char *value = NULL;
    int status;
    if (destination_size == 0U) {
        return -1;
    }
    destination[0] = '\0';
    status = XGetWindowProperty(display, window, property, 0L, 1024L, False, AnyPropertyType,
                                &actual_type, &actual_format, &item_count, &bytes_after, &value);
    if (status != Success || value == NULL || actual_format != 8 || bytes_after != 0UL) {
        if (value != NULL) {
            XFree(value);
        }
        return -1;
    }
    if (item_count >= destination_size) {
        XFree(value);
        return -1;
    }
    memcpy(destination, value, item_count);
    destination[item_count] = '\0';
    XFree(value);
    return 0;
}

static int read_window_pid(Display *display, Window window, unsigned long *pid) {
    Atom property = XInternAtom(display, "_NET_WM_PID", False);
    Atom actual_type = None;
    int actual_format = 0;
    unsigned long item_count = 0UL;
    unsigned long bytes_after = 0UL;
    unsigned char *value = NULL;
    int status = XGetWindowProperty(display, window, property, 0L, 1L, False, XA_CARDINAL,
                                    &actual_type, &actual_format, &item_count, &bytes_after, &value);
    if (status != Success || value == NULL || actual_type != XA_CARDINAL || actual_format != 32 ||
        item_count != 1UL || bytes_after != 0UL) {
        if (value != NULL) {
            XFree(value);
        }
        return -1;
    }
    *pid = *((unsigned long *)value);
    XFree(value);
    return 0;
}

static int inspect_viewer_candidate(Display *display, Window window, unsigned long expected_pid,
                                    ViewerWindow *candidate) {
    XWindowAttributes attributes;
    XClassHint hint = {0};
    Atom net_name = XInternAtom(display, "_NET_WM_NAME", False);
    char title[512] = {0};
    unsigned long pid = 0UL;
    if (XGetWindowAttributes(display, window, &attributes) == 0 ||
        attributes.map_state != IsViewable || attributes.width < 500 || attributes.height < 350) {
        return 0;
    }
    if (read_text_property(display, window, net_name, title, sizeof(title)) != 0) {
        char *legacy = NULL;
        if (XFetchName(display, window, &legacy) == 0 || legacy == NULL) {
            return 0;
        }
        if (strlen(legacy) >= sizeof(title)) {
            XFree(legacy);
            return 0;
        }
        strcpy(title, legacy);
        XFree(legacy);
    }
    if (strstr(title, "127.0.0.1 - Control Remote Desktop") == NULL) {
        return 0;
    }
    if (read_window_pid(display, window, &pid) != 0 || pid != expected_pid) {
        return 0;
    }
    if (XGetClassHint(display, window, &hint) == 0 || hint.res_name == NULL ||
        hint.res_class == NULL || strcmp(hint.res_name, "rustdesk") != 0 ||
        strcmp(hint.res_class, "Rustdesk") != 0) {
        if (hint.res_name != NULL) {
            XFree(hint.res_name);
        }
        if (hint.res_class != NULL) {
            XFree(hint.res_class);
        }
        return 0;
    }
    candidate->window = window;
    candidate->width = (unsigned int)attributes.width;
    candidate->height = (unsigned int)attributes.height;
    candidate->pid = pid;
    strcpy(candidate->title, title);
    if (strlen(hint.res_name) >= sizeof(candidate->instance_name) ||
        strlen(hint.res_class) >= sizeof(candidate->class_name)) {
        XFree(hint.res_name);
        XFree(hint.res_class);
        return -1;
    }
    strcpy(candidate->instance_name, hint.res_name);
    strcpy(candidate->class_name, hint.res_class);
    XFree(hint.res_name);
    XFree(hint.res_class);
    return 1;
}

static int find_viewer_window(Display *display, unsigned long expected_pid, ViewerWindow *viewer) {
    Window root = RootWindow(display, DefaultScreen(display));
    uint64_t deadline = monotonic_millis() + WINDOW_WAIT_MS;
    while (monotonic_millis() < deadline) {
        Window returned_root;
        Window returned_parent;
        Window *children = NULL;
        unsigned int child_count = 0U;
        unsigned int index;
        unsigned int matches = 0U;
        ViewerWindow found = {0};
        if (XQueryTree(display, root, &returned_root, &returned_parent, &children, &child_count) == 0) {
            return -1;
        }
        for (index = 0U; index < child_count; ++index) {
            ViewerWindow candidate = {0};
            int status = inspect_viewer_candidate(display, children[index], expected_pid, &candidate);
            if (status < 0) {
                XFree(children);
                return -1;
            }
            if (status > 0) {
                found = candidate;
                matches += 1U;
            }
        }
        if (children != NULL) {
            XFree(children);
        }
        if (matches == 1U) {
            *viewer = found;
            return 0;
        }
        if (matches > 1U) {
            fprintf(stderr, "FLUTTER_PEER_X11_FAIL multiple exact remote windows=%u\n", matches);
            return -1;
        }
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static int fake_key(Display *display, KeySym symbol) {
    KeyCode code = XKeysymToKeycode(display, symbol);
    if (code == 0U || XTestFakeKeyEvent(display, code, True, CurrentTime) == 0 ||
        XTestFakeKeyEvent(display, code, False, CurrentTime) == 0) {
        return -1;
    }
    XSync(display, False);
    return sleep_millis(PASSWORD_KEY_INTERVAL_MS);
}

static int type_password(Display *display) {
    size_t index;
    for (index = 0U; index < sizeof(test_password) - 1U; ++index) {
        KeySym symbol;
        unsigned char character = (unsigned char)test_password[index];
        if (character == '-') {
            symbol = XK_minus;
        } else if ((character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9')) {
            symbol = (KeySym)character;
        } else {
            return -1;
        }
        if (fake_key(display, symbol) != 0) {
            return -1;
        }
    }
    return 0;
}

static int wait_for_current_frames(Display *display, const ViewerWindow *viewer,
                                   SourceHistory *history, unsigned int timeout_ms,
                                   unsigned int required_distinct, uint64_t *first_fresh_ms,
                                   uint64_t *maximum_age_ms) {
    enum { OBSERVATION_LIMIT = 64 };
    struct {
        uint64_t elapsed_ms, captured_us, age_ms;
        int64_t state, latest_published;
        int age_valid, admitted;
    } observations[OBSERVATION_LIMIT];
    uint64_t start = monotonic_millis();
    uint64_t deadline = start + timeout_ms;
    uint64_t previous = start;
    uint64_t samples = 0U, valid_age_samples = 0U;
    int64_t last_state = -1;
    unsigned int distinct = 0U, retained = 0U, next = 0U;
    int saw_fresh = 0, saved_errno;
    const char *failure = "deadline";
    *first_fresh_ms = 0U;
    *maximum_age_ms = 0U;
    if (start == 0U || deadline < start) {
        failure = "clock";
        goto failed;
    }
    for (;;) {
        uint64_t now, captured_us = 0U;
        int64_t state;
        uint64_t age = 0U;
        int age_valid;
        now = monotonic_millis();
        if (now == 0U || now < previous) {
            failure = "clock";
            break;
        }
        previous = now;
        if (now >= deadline) break;
        state = viewer_state(display, viewer, &captured_us);
        age_valid = x11_frame_age(history, "/coord", state, captured_us, &age) == 0;
        now = monotonic_millis();
        if (now == 0U || now < previous) {
            failure = "clock";
            break;
        }
        previous = now;
        observations[next].elapsed_ms = now - start;
        observations[next].captured_us = captured_us;
        observations[next].age_ms = age;
        observations[next].state = state;
        observations[next].latest_published = (int64_t)history->count - 1;
        observations[next].age_valid = age_valid;
        observations[next].admitted = !history->failed && now < deadline &&
                                      age_valid && age <= FRESH_LIMIT_MS;
        next = (next + 1U) % OBSERVATION_LIMIT;
        if (retained < OBSERVATION_LIMIT) retained += 1U;
        samples += 1U;
        if (age_valid) valid_age_samples += 1U;
        if (age_valid && age > *maximum_age_ms) {
            *maximum_age_ms = age;
        }
        if (history->failed || now >= deadline) {
            if (history->failed) failure = "source-history";
            break;
        }
        if (age_valid && age <= FRESH_LIMIT_MS) {
            if (saw_fresh == 0) {
                *first_fresh_ms = now - start;
                saw_fresh = 1;
            }
            if (state > last_state) {
                last_state = state;
                distinct += 1U;
            }
            if (distinct >= required_distinct) {
                return 0;
            }
        }
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            failure = "sample-sleep";
            break;
        }
    }
failed:
    saved_errno = errno;
    fprintf(stderr, "FLUTTER_PEER_FRESHNESS_WAIT_FAILED reason=%s timeout_ms=%u "
            "required=%u distinct=%u samples=%llu valid_age_samples=%llu "
            "saw_fresh=%s first_fresh_ms=%llu maximum_observed_age_ms=%llu "
            "retained=%u dropped=%llu errno=%d\n", failure, timeout_ms,
            required_distinct, distinct, (unsigned long long)samples,
            (unsigned long long)valid_age_samples, saw_fresh ? "true" : "false",
            (unsigned long long)*first_fresh_ms, (unsigned long long)*maximum_age_ms,
            retained, (unsigned long long)(samples - retained), saved_errno);
    for (unsigned int index = 0U; index < retained; ++index) {
        unsigned int slot = (next + OBSERVATION_LIMIT - retained + index) % OBSERVATION_LIMIT;
        fprintf(stderr, "FLUTTER_PEER_FRESHNESS_SAMPLE index=%llu elapsed_ms=%llu "
                "state=%lld latest_published=%lld captured_us=%llu age_valid=%s "
                "age_ms=%llu admitted=%s\n", (unsigned long long)(samples - retained + index),
                (unsigned long long)observations[slot].elapsed_ms,
                (long long)observations[slot].state, (long long)observations[slot].latest_published,
                (unsigned long long)observations[slot].captured_us,
                observations[slot].age_valid ? "true" : "false",
                (unsigned long long)observations[slot].age_ms,
                observations[slot].admitted ? "true" : "false");
    }
    errno = saved_errno;
    return -1;
}

static int observe_current_frames_for_duration(Display *source, Display *display,
                                               const ViewerWindow *viewer,
                                               SourceHistory *history,
                                               unsigned int duration_ms,
                                               uint64_t *maximum_gap_ms,
                                               uint64_t *maximum_age_ms,
                                               unsigned int *distinct_states) {
    uint64_t start = monotonic_millis();
    uint64_t deadline = start + duration_ms;
    uint64_t previous = start;
    uint64_t last_fresh = start;
    int64_t last_state = -1;
    const char *trace_value = getenv("RUSTDESK_PRESENTATION_TRACE");
    int trace_enabled = trace_value != NULL && strcmp(trace_value, "1") == 0;

    *maximum_gap_ms = 0U;
    *maximum_age_ms = 0U;
    *distinct_states = 0U;
    if (start == 0U || deadline < start) return -1;
    for (;;) {
        uint64_t now, captured_us = 0U;
        uint64_t age;
        uint64_t gap;
        int64_t state;
        int64_t observed_source_state = -1;
        int age_valid;
        int fresh;

        now = monotonic_millis();
        if (now == 0U || now < previous) return -1;
        previous = now;
        if (now >= deadline) break;
        if (trace_enabled) {
            observed_source_state = source_state(source);
        }
        state = viewer_state(display, viewer, &captured_us);
        age_valid = x11_frame_age(history, "/coord", state, captured_us, &age) == 0;
        now = monotonic_millis();
        if (now == 0U || now < previous) return -1;
        previous = now;
        if (age_valid && age > *maximum_age_ms) {
            *maximum_age_ms = age;
        }
        if (history->failed) {
            return -1;
        }
        gap = (now < deadline ? now : deadline) - last_fresh;
        fresh = now < deadline && age_valid && age <= FRESH_LIMIT_MS;
        if (fresh) {
            last_fresh = now;
            if (state > last_state) {
                last_state = state;
                *distinct_states += 1U;
            }
        }
        if (gap > *maximum_gap_ms) {
            *maximum_gap_ms = gap;
        }
        if (trace_enabled != 0) {
            printf("RUSTDESK_PRESENTATION_TRACE stage=observer monotonic_ms=%llu "
                   "source_state=%lld viewer_state=%lld age_ms=%lld fresh=%d gap_ms=%llu\n",
                   (unsigned long long)now, (long long)observed_source_state, (long long)state,
                   age_valid ? (long long)age : -1LL, fresh,
                   (unsigned long long)gap);
            fflush(stdout);
        }
        if (gap > FRESH_LIMIT_MS || sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    uint64_t final_gap = deadline - last_fresh;
    if (final_gap > *maximum_gap_ms) {
        *maximum_gap_ms = final_gap;
    }
    return final_gap <= FRESH_LIMIT_MS && *distinct_states >= duration_ms / 1000U ? 0 : -1;
}

static int read_connection_identity(ConnectionIdentity *identity) {
    FILE *stream = fopen("/proc/net/tcp", "r");
    char line[512];
    unsigned int matches = 0U;
    if (stream == NULL) {
        return -1;
    }
    if (fgets(line, sizeof(line), stream) == NULL) {
        fclose(stream);
        return -1;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        unsigned int slot;
        char local[32];
        char remote[32];
        char state[3];
        unsigned long inode;
        int fields = sscanf(line,
                            " %u: %31s %31s %2s %*s %*s %*s %*s %*s %lu",
                            &slot, local, remote, state, &inode);
        (void)slot;
        if (fields == 5 && strcmp(state, "01") == 0 &&
            strcmp(remote, "0100007F:527E") == 0) {
            if (strlen(local) >= sizeof(identity->local) ||
                strlen(remote) >= sizeof(identity->remote)) {
                fclose(stream);
                return -1;
            }
            strcpy(identity->local, local);
            strcpy(identity->remote, remote);
            identity->inode = inode;
            matches += 1U;
        }
    }
    if (ferror(stream) != 0 || fclose(stream) != 0 || matches != 1U) {
        return -1;
    }
    return 0;
}

static int same_connection(const ConnectionIdentity *left, const ConnectionIdentity *right) {
    return strcmp(left->local, right->local) == 0 &&
           strcmp(left->remote, right->remote) == 0 && left->inode == right->inode;
}

static int wait_for_replacement_connection(const ConnectionIdentity *previous,
                                           ConnectionIdentity *replacement) {
    uint64_t deadline = monotonic_millis() + RECONNECT_LIMIT_MS;
    while (monotonic_millis() < deadline) {
        ConnectionIdentity candidate = {{0}, {0}, 0UL};
        if (read_connection_identity(&candidate) == 0 &&
            same_connection(previous, &candidate) == 0) {
            *replacement = candidate;
            return 0;
        }
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static int count_directory_entries(const char *path, unsigned int *count) {
    DIR *directory = opendir(path);
    struct dirent *entry;
    unsigned int value = 0U;
    int iteration_error;
    int close_status;
    if (directory == NULL) {
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            if (value == UINT_MAX) {
                closedir(directory);
                return -1;
            }
            value += 1U;
        }
    }
    iteration_error = errno;
    close_status = closedir(directory);
    if (iteration_error != 0 || close_status != 0) {
        return -1;
    }
    *count = value;
    return 0;
}

static int read_process_resources(unsigned long pid, ProcessResources *resources) {
    char path[64];
    char line[256];
    FILE *status;
    int saw_rss = 0;
    int saw_threads = 0;
    int length = snprintf(path, sizeof(path), "/proc/%lu/status", pid);
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }
    status = fopen(path, "r");
    if (status == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "VmRSS: %llu kB", &resources->rss_kib) == 1) {
            saw_rss = 1;
        } else if (sscanf(line, "Threads: %u", &resources->threads) == 1) {
            saw_threads = 1;
        }
    }
    if (ferror(status) != 0 || fclose(status) != 0 || saw_rss == 0 || saw_threads == 0) {
        return -1;
    }
    length = snprintf(path, sizeof(path), "/proc/%lu/fd", pid);
    if (length <= 0 || (size_t)length >= sizeof(path) ||
        count_directory_entries(path, &resources->descriptors) != 0) {
        return -1;
    }
    return 0;
}

static int resources_are_bounded(const ProcessResources *baseline,
                                 const ProcessResources *current) {
    return current->threads <= baseline->threads + RESOURCE_THREAD_GROWTH_LIMIT &&
           current->descriptors <= baseline->descriptors + RESOURCE_FD_GROWTH_LIMIT &&
           current->rss_kib <= baseline->rss_kib + RESOURCE_RSS_GROWTH_KIB_LIMIT;
}

static void print_resources(const char *phase, unsigned int sequence,
                            const ProcessResources *resources) {
    printf("FLUTTER_PEER_RESOURCE_SAMPLE phase=%s sequence=%u rss_kib=%llu threads=%u fds=%u\n",
           phase, sequence, resources->rss_kib, resources->threads,
           resources->descriptors);
}

/* GTK owns the synthetic source selection. A separate Xlib connection reads the
 * destination selection; only the two real applications can transfer between them. */
typedef struct {
    char text[16385];
    GdkPixbuf *image;
    size_t supplied_bytes;
    unsigned int requests;
    int released;
    int failed;
} ClipboardFixture;

static void clipboard_fixture_get(GtkClipboard *clipboard, GtkSelectionData *selection,
                                   guint info, gpointer user_data) {
    ClipboardFixture *fixture = user_data;
    (void)clipboard;
    (void)info;
    fixture->requests += 1U;
    gboolean supplied = fixture->image != NULL ?
        gtk_selection_data_set_pixbuf(selection, fixture->image) :
        gtk_selection_data_set_text(selection, fixture->text, -1);
    if (!supplied) fixture->failed = 1;
    else fixture->supplied_bytes = (size_t)gtk_selection_data_get_length(selection);
}

static void clipboard_fixture_clear(GtkClipboard *clipboard, gpointer user_data) {
    (void)clipboard;
    ((ClipboardFixture *)user_data)->released = 1;
}

static GdkPixbuf *clipboard_fixture_image(unsigned int sequence) {
    unsigned int kind = (sequence - 7U) / 2U;
    int width = kind == 0U ? 1 : kind == 1U ? 17 : kind == 2U ? 63 :
        kind == 3U ? 513 : 2051;
    int height = kind == 0U ? 1 : kind == 1U ? 13 : kind == 2U ? 31 :
        kind == 3U ? 515 : 2053;
    GdkPixbuf *image = gdk_pixbuf_new(GDK_COLORSPACE_RGB, kind != 2U, 8, width, height);
    if (image == NULL) return NULL;
    int channels = gdk_pixbuf_get_n_channels(image);
    int stride = gdk_pixbuf_get_rowstride(image);
    guchar *pixels = gdk_pixbuf_get_pixels(image);
    static const guchar alpha[] = {0, 64, 128, 255};
    uint32_t noise = 0x9e3779b9U ^ sequence;
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            guchar *pixel = pixels + y * stride + x * channels;
            pixel[0] = (guchar)(x * 31 + y * 7 + sequence * 13U);
            pixel[1] = (guchar)(x * 3 + y * 43 + sequence * 17U);
            pixel[2] = (guchar)(x * 19 + y * 11 + sequence * 23U);
            if (channels == 4) pixel[3] = alpha[(x + y) % 4];
            if (kind >= 3U) {
                /* Fixed seed, full-byte entropy: PNG must not collapse the large case. */
                noise ^= noise << 13;
                noise ^= noise >> 17;
                noise ^= noise << 5;
                for (int c = 0; c < channels; ++c)
                    pixel[c] = (guchar)(noise >> (8 * c));
            }
        }
    }
    return image;
}

static int clipboard_image_matches(GdkPixbuf *expected, const unsigned char *data,
                                    size_t length) {
    GError *error = NULL;
    GdkPixbufLoader *loader = gdk_pixbuf_loader_new_with_type("png", &error);
    int matched = 0;
    if (loader == NULL) goto done;
    gboolean written = gdk_pixbuf_loader_write(loader, data, length, &error);
    /* Close even after a decoding error, but never reuse a populated GError. */
    gboolean closed = gdk_pixbuf_loader_close(loader, written ? &error : NULL);
    if (!written || !closed) goto done;
    GdkPixbuf *actual = gdk_pixbuf_loader_get_pixbuf(loader);
    int width = gdk_pixbuf_get_width(expected), height = gdk_pixbuf_get_height(expected);
    if (actual == NULL || gdk_pixbuf_get_width(actual) != width ||
        gdk_pixbuf_get_height(actual) != height ||
        gdk_pixbuf_get_colorspace(actual) != GDK_COLORSPACE_RGB ||
        gdk_pixbuf_get_bits_per_sample(actual) != 8) goto done;
    int expected_channels = gdk_pixbuf_get_n_channels(expected);
    int actual_channels = gdk_pixbuf_get_n_channels(actual);
    if (actual_channels != 3 && actual_channels != 4) goto done;
    const guchar *a = gdk_pixbuf_read_pixels(actual), *e = gdk_pixbuf_read_pixels(expected);
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            const guchar *ap = a + y * gdk_pixbuf_get_rowstride(actual) + x * actual_channels;
            const guchar *ep = e + y * gdk_pixbuf_get_rowstride(expected) + x * expected_channels;
            if (memcmp(ap, ep, 3U) != 0 ||
                (actual_channels == 4 ? ap[3] : 255) !=
                (expected_channels == 4 ? ep[3] : 255)) goto done;
        }
    }
    matched = 1;
done:
    if (error != NULL) g_error_free(error);
    if (loader != NULL) g_object_unref(loader);
    return matched;
}

static int exercise_clipboard(Display *source, Display *display,
                                   const ViewerWindow *viewer,
                                   const ConnectionIdentity *connection,
                                   const ProcessResources *baseline, int include_images) {
    enum { TEXT_LIMIT = 16384, READ_LIMIT = 24 * 1024 * 1024,
           TRANSFER_LIMIT_MS = 5000, CASES = 18 };
    GdkDisplay *gtk_displays[2] = {NULL, NULL};
    GtkClipboard *clipboards[2] = {NULL, NULL};
    Display *displays[2] = {source, display};
    Window fixture_owners[2] = {None, None};
    Window requestor = None;
    Display *destination = NULL;
    int status = -1;
    const char *phase = "gtk-init";
    unsigned int sequence = 0U;
    ClipboardFixture fixtures[CASES] = {0};
    unsigned char *received = malloc(READ_LIMIT);

    if (received == NULL || !gtk_init_check(NULL, NULL)) goto done;
    gtk_displays[0] = gdk_display_open(DisplayString(source));
    gtk_displays[1] = gdk_display_get_default();
    if (gtk_displays[0] == NULL || gtk_displays[1] == NULL ||
        strcmp(gdk_display_get_name(gtk_displays[1]), DisplayString(display)) != 0)
        goto done;
    for (unsigned int side = 0U; side < 2U; ++side) {
        clipboards[side] = gtk_clipboard_get_for_display(gtk_displays[side],
                                                       GDK_SELECTION_CLIPBOARD);
        if (clipboards[side] == NULL) goto done;
    }
    for (sequence = 1U; sequence <= (include_images ? CASES : 6U); ++sequence) {
        ClipboardFixture *fixture = &fixtures[sequence - 1U];
        char *text = fixture->text;
        unsigned int from = sequence % 2U;
        unsigned int to = 1U - from;
        Atom selection = XInternAtom(displays[from], "CLIPBOARD", False);
        Atom target, property;
        uint64_t start, now, next_request = 0U;
        int pending = 0, matched = 0, incremental = 0;
        unsigned int chunks = 0U;
        size_t received_bytes = 0U;
        unsigned int replies = 0U;
        unsigned long last_count = 0UL, last_remaining = 0UL;
        Atom last_type = None;
        int last_format = 0;
        size_t length;
        int is_image = sequence > 6U && sequence <= 16U;
        int large_image = sequence >= 13U && sequence <= 16U;
        const char *kind = sequence <= 2U ? "ascii" : sequence <= 4U ? "unicode" :
            sequence <= 6U ? "16k" : sequence <= 8U ? "transparent-1x1" :
            sequence <= 10U ? "rgba-17x13" : sequence <= 12U ? "rgb-63x31" :
            sequence <= 14U ? "rgba-513x515" : sequence <= 16U ? "rgba-2051x2053" :
            "text-after-images";
        ConnectionIdentity after = {{0}, {0}, 0UL};
        ProcessResources resources = {0};
        ViewerWindow current = {0};
        int prefix = snprintf(text, sizeof(fixture->text), "clipboard-%u-%s\n", sequence, kind);
        if (prefix <= 0 || (size_t)prefix >= sizeof(fixture->text)) goto done;
        length = (size_t)prefix;
        if (is_image) {
            fixture->image = clipboard_fixture_image(sequence);
            if (fixture->image == NULL) goto done;
        } else if (sequence <= 4U || sequence > 16U) {
            const char *body = sequence <= 2U ? "line one\nline two\tend" :
                "caf\xc3\xa9 e\xcc\x81 \xd7\xa9\xd7\x9c\xd7\x95\xd7\x9d "
                "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xf0\x9f\x99\x82\nlast line";
            size_t body_length = strlen(body);
            if (length + body_length >= sizeof(fixture->text)) goto done;
            memcpy(text + length, body, body_length + 1U);
            length += body_length;
        } else {
            for (; length < TEXT_LIMIT; ++length)
                text[length] = (char)('a' + (length + sequence) % 26U);
            text[length] = '\0';
        }

        destination = displays[to];
        requestor = XCreateSimpleWindow(destination, DefaultRootWindow(destination),
                                         0, 0, 1U, 1U, 0U, 0UL, 0UL);
        if (requestor == None) goto done;
        XSelectInput(destination, requestor, PropertyChangeMask);
        target = XInternAtom(destination, is_image ? "image/png" : "UTF8_STRING", False);
        Atom incr = XInternAtom(destination, "INCR", False);
        property = XInternAtom(destination, "_RUSTDESK_CLIPBOARD_EVIDENCE", False);
        phase = "source-ownership";
        start = monotonic_millis();
        if (start == 0U) goto done;
        GtkTargetList *targets = gtk_target_list_new(NULL, 0U);
        if (is_image)
            gtk_target_list_add(targets, gdk_atom_intern_static_string("image/png"), 0U, 0U);
        else
            gtk_target_list_add_text_targets(targets, 0U);
        gint target_count = 0;
        GtkTargetEntry *entries = gtk_target_table_new_from_list(targets, &target_count);
        gboolean owned = gtk_clipboard_set_with_data(clipboards[from], entries, target_count,
            clipboard_fixture_get, clipboard_fixture_clear, fixture);
        gtk_target_table_free(entries, target_count);
        gtk_target_list_unref(targets);
        if (!owned) goto done;
        gdk_display_sync(gtk_displays[from]);
        fixture_owners[from] = XGetSelectionOwner(displays[from], selection);
        if (fixture_owners[from] == None) goto done;
        printf("FLUTTER_PEER_CLIPBOARD_SOURCE sequence=%u owner=%lu\n", sequence,
               fixture_owners[from]);
        if (large_image)
            printf("FLUTTER_PEER_CLIPBOARD_X11_LIMIT sequence=%u maximum_request_bytes=%ld\n",
                   sequence, 4L * XExtendedMaxRequestSize(destination));
        selection = XInternAtom(destination, "CLIPBOARD", False);
        phase = "destination-readback";
        while ((now = monotonic_millis()) >= start && now - start < TRANSFER_LIMIT_MS) {
            XEvent event;
            /* Bounded pumping serves native selection requests on both displays. */
            for (unsigned int i = 0U; i < 64U && g_main_context_pending(NULL); ++i)
                g_main_context_iteration(NULL, FALSE);
            int have_reply = pending && !incremental &&
                XCheckTypedWindowEvent(destination, requestor, SelectionNotify, &event);
            int have_chunk = 0;
            if (!have_reply) {
                /* Drain pre-INCR property notices before acknowledging its header;
                 * a stale notice must not be mistaken for the terminal empty chunk. */
                for (unsigned int i = 0U; i < 64U &&
                     XCheckTypedWindowEvent(destination, requestor, PropertyNotify, &event); ++i) {
                    if (pending && incremental && event.xproperty.atom == property &&
                        event.xproperty.state == PropertyNewValue) {
                        have_chunk = 1;
                        break;
                    }
                }
            }
            if (have_reply || have_chunk) {
                unsigned char *data = NULL;
                Atom actual_type = None;
                int format = 0;
                unsigned long count = 0UL, remaining = 0UL;
                if (have_reply) {
                    replies += 1U;
                    if (event.xselection.selection != selection ||
                        event.xselection.target != target) goto done;
                    if (event.xselection.property == None) {
                        pending = 0;
                        next_request = now + 100U;
                        continue;
                    }
                    if (event.xselection.property != property) goto done;
                }
                {
                    if (XGetWindowProperty(destination, requestor, property, 0L,
                            READ_LIMIT / 4L, False, AnyPropertyType, &actual_type,
                            &format, &count, &remaining, &data) != Success) {
                        if (data != NULL) XFree(data);
                        goto done;
                    }
                    if (have_reply && actual_type == incr) {
                        int valid = format == 32 && count == 1UL && remaining == 0UL &&
                            data != NULL && *(unsigned long *)data <= READ_LIMIT;
                        if (data != NULL) XFree(data);
                        if (!valid) goto done;
                        /* No next chunk can arrive before this deletion. */
                        while (XCheckTypedWindowEvent(destination, requestor, PropertyNotify, &event)) {}
                        incremental = 1;
                        XDeleteProperty(destination, requestor, property);
                        XFlush(destination);
                        continue;
                    }
                    if (actual_type != target || format != 8 || remaining != 0UL ||
                        count > READ_LIMIT - received_bytes || (count != 0 && data == NULL)) {
                        if (data != NULL) XFree(data);
                        goto done;
                    }
                    if (count != 0) memcpy(received + received_bytes, data, count);
                    received_bytes += count;
                    if (incremental && count != 0) chunks += 1U;
                    int complete = !incremental || count == 0UL;
                    matched = complete && (is_image ?
                        clipboard_image_matches(fixture->image, received, received_bytes) :
                        received_bytes == length && memcmp(received, text, length) == 0);
                    last_type = actual_type;
                    last_format = format;
                    last_count = received_bytes;
                    last_remaining = remaining;
                    if (data != NULL) XFree(data);
                    XDeleteProperty(destination, requestor, property);
                    XFlush(destination);
                    if (complete) {
                        pending = 0;
                        if (!matched) { received_bytes = 0U; incremental = 0; chunks = 0U; }
                    }
                }
                if (matched) {
                    Window owner = XGetSelectionOwner(destination, selection);
                    if (owner == None || owner == fixture_owners[to]) goto done;
                    break;
                }
                next_request = now + 100U;
            }
            if (!pending && now >= next_request) {
                Window owner = XGetSelectionOwner(destination, selection);
                /* A read of our preceding source owner cannot prove remote delivery
                 * and may remain unanswered as that selection is replaced. */
                if (owner != None && owner != fixture_owners[to]) {
                    XConvertSelection(destination, selection, target, property, requestor, CurrentTime);
                    XFlush(destination);
                    pending = 1;
                }
            }
            /* Service the source GTK event loop promptly during its INCR handshake. */
            if (sleep_millis(large_image ? 1U : 10U) != 0) goto done;
        }
        now = monotonic_millis();
        printf("FLUTTER_PEER_CLIPBOARD_READ sequence=%u pending=%d replies=%u "
               "type=%lu expected_type=%lu format=%d bytes=%lu remaining=%lu\n",
               sequence, pending, replies, last_type, target, last_format,
               last_count, last_remaining);
        printf("FLUTTER_PEER_CLIPBOARD_OBSERVED sequence=%u requests=%u released=%d "
               "conversion_failed=%d matched=%d supplied_bytes=%zu incremental=%d chunks=%u "
               "source_owner=%lu destination_owner=%lu\n",
               sequence, fixture->requests, fixture->released, fixture->failed, matched,
               fixture->supplied_bytes, incremental, chunks,
               XGetSelectionOwner(displays[from], XInternAtom(displays[from], "CLIPBOARD", False)),
               XGetSelectionOwner(destination, selection));
        if (!matched || fixture->failed || fixture->requests == 0U ||
            now < start || now - start >= TRANSFER_LIMIT_MS) goto done;
        if (large_image && fixture->supplied_bytes <= (sequence <= 14U ? 1024U * 1024U :
                                                       16U * 1024U * 1024U)) goto done;
        phase = "connection-and-resources";
        if (read_connection_identity(&after) != 0 || !same_connection(connection, &after) ||
            find_viewer_window(display, viewer->pid, &current) != 0 ||
            current.window != viewer->window ||
            read_process_resources(viewer->pid, &resources) != 0) goto done;
        print_resources("clipboard", sequence, &resources);
        if (!resources_are_bounded(baseline, &resources)) goto done;
        printf("FLUTTER_PEER_CLIPBOARD_CASE_OK sequence=%u direction=%s kind=%s bytes=%lu "
               "elapsed_ms=%llu exact_%s=true destination_owner=external\n",
               sequence, from == 1U ? "viewer-to-controlled" : "controlled-to-viewer", kind,
               last_count, (unsigned long long)(now - start), is_image ? "pixels" : "utf8");
        fflush(stdout);
        XDestroyWindow(destination, requestor);
        requestor = None;
    }
    status = 0;
done:
    if (status != 0)
        fprintf(stderr, "FLUTTER_PEER_CLIPBOARD_FAIL sequence=%u phase=%s\n", sequence, phase);
    if (requestor != None) XDestroyWindow(destination, requestor);
    for (unsigned int side = 0U; side < 2U; ++side)
        if (gtk_displays[side] != NULL) gdk_display_close(gtk_displays[side]);
    for (unsigned int i = 0U; i < CASES; ++i)
        if (fixtures[i].image != NULL) g_object_unref(fixtures[i].image);
    free(received);
    return status;
}

/* The stage owns the child and supplies its creation identity. Keep both a
 * procfs directory and a pidfd; never reacquire a numeric PID to resume the viewer. */
static int viewer_process_state(int process, unsigned long pid, const char *start,
                                 char *state) {
    char record[4096], prefix[32];
    char *cursor, *end;
    int descriptor = openat(process, "stat", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    ssize_t length;
    int result = -1;
    if (descriptor < 0) return -1;
    do {
        length = read(descriptor, record, sizeof(record) - 1U);
    } while (length < 0 && errno == EINTR);
    if (length <= 0 || (size_t)length == sizeof(record) - 1U) goto finished;
    record[length] = '\0';
    if (snprintf(prefix, sizeof(prefix), "%lu (", pid) <= 0 ||
        strncmp(record, prefix, strlen(prefix)) != 0) goto finished;
    cursor = strrchr(record, ')');
    if (cursor == NULL || cursor[1] != ' ') goto finished;
    cursor += 2;
    for (unsigned int field = 3U; field <= 22U; ++field) {
        end = strchr(cursor, ' ');
        if (end == NULL || end == cursor) goto finished;
        if (field == 3U) {
            if (end != cursor + 1 || strchr("RSDTtZIXP", *cursor) == NULL ||
                strchr("ZIX", *cursor) != NULL) goto finished;
            *state = *cursor;
        } else if (field == 22U &&
                   ((size_t)(end - cursor) != strlen(start) ||
                    strncmp(cursor, start, (size_t)(end - cursor)) != 0)) {
            goto finished;
        }
        cursor = end + 1;
    }
    result = 0;
finished:
    if (close(descriptor) != 0) result = -1;
    return result;
}

static int viewer_pidfd_alive(int pidfd) {
    struct pollfd descriptor = {.fd = pidfd, .events = POLLIN};
    int result;
    do {
        result = poll(&descriptor, 1U, 0);
    } while (result < 0 && errno == EINTR);
    return result == 0;
}

static int network_profile(const char *profile, unsigned long long *drops,
                           unsigned long long *packets) {
    struct sockaddr_un address = {.sun_family = AF_UNIX, .sun_path = "/netem.sock"};
    struct timeval timeout = {.tv_sec = 5};
    struct ucred peer = {0};
    socklen_t peer_size = sizeof(peer);
    char reply[128];
    unsigned long long applied_us, queued;
    int consumed = 0, result = -1;
    int descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    ssize_t count;
    if (descriptor < 0) return -1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0 ||
        connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
        peer_size != sizeof(peer) || peer.uid != 0 || peer.gid != 0 ||
        send(descriptor, profile, strlen(profile), MSG_NOSIGNAL) != (ssize_t)strlen(profile))
        goto finished;
    count = recv(descriptor, reply, sizeof(reply) - 1U, MSG_TRUNC);
    if (count <= 0 || count >= (ssize_t)sizeof(reply)) goto finished;
    reply[count] = '\0';
    if (sscanf(reply, "OK %llu %llu %llu %llu%n", &applied_us, drops, packets, &queued,
               &consumed) != 4 || reply[consumed] != '\0' || queued > 64ULL ||
        applied_us == 0ULL || applied_us / 1000ULL > monotonic_millis()) goto finished;
    result = 0;
finished:
    if (close(descriptor) != 0) result = -1;
    return result;
}

static int exercise_network_impairment(Display *source, Display *display,
                                      ViewerWindow *viewer, SourceHistory *history,
                                      unsigned long pid, const ConnectionIdentity *connection,
                                      const ProcessResources *baseline, int partial_loss) {
    const struct {
        const char *profile;
        unsigned int hold_ms;
    } outage_cases[] = {
        /* Quarter-second restoration offsets around the original two outages. */
        {"delay", 6000U}, {"loss", 2000U}, {"loss", 6000U},
        {"loss", 1750U}, {"loss", 5750U}, {"loss", 2250U},
        {"loss", 6250U}, {"loss", 2500U}, {"loss", 6500U},
    }, loss_cases[] = {
        {"random3", 20000U}, {"random8", 20000U}, {"burst", 20000U},
    };
    uint64_t max_gap = 0U, max_age = 0U;
    unsigned int distinct = 0U, cycle = 0U;
    unsigned long long before_drops = 0ULL, before_packets = 0ULL;
    unsigned long long after_drops = 0ULL, after_packets = 0ULL;
    const char *phase = "healthy-baseline";
    if (observe_current_frames_for_duration(source, display, viewer, history, 3000U,
                                            &max_gap, &max_age, &distinct) != 0 ||
        max_age > FRESH_LIMIT_MS) goto failed;
    printf("FLUTTER_PEER_NETWORK_BASELINE_OK duration_ms=3000 maximum_age_ms=%llu distinct=%u\n",
           (unsigned long long)max_age, distinct);
    for (; cycle < (partial_loss ? sizeof(loss_cases) / sizeof(loss_cases[0])
                               : sizeof(outage_cases) / sizeof(outage_cases[0])); ++cycle) {
        const char *profile = partial_loss ? loss_cases[cycle].profile : outage_cases[cycle].profile;
        unsigned int hold_ms = partial_loss ? loss_cases[cycle].hold_ms : outage_cases[cycle].hold_ms;
        uint64_t held_from, progress_at, resumed_at, first_fresh, recovery_age, recovery_ms;
        uint64_t impaired_maximum_age = 0U;
        unsigned int impaired_distinct = 0U;
        int64_t previous_source, initial_source, previous_viewer = -1;
        ConnectionIdentity after = {{0}, {0}, 0UL};
        ViewerWindow same_viewer = {0};
        ProcessResources resources = {0};
        phase = "apply-impairment";
        if (network_profile(profile, &before_drops, &before_packets) != 0)
            goto failed;
        initial_source = previous_source = source_state(source);
        held_from = progress_at = monotonic_millis();
        phase = "impaired-source-progress";
        if (initial_source < 0) goto failed;
        while (monotonic_millis() - held_from < hold_ms) {
            int64_t current = source_state(source);
            uint64_t now = monotonic_millis();
            if (current < previous_source || now - progress_at > FRESH_LIMIT_MS) goto failed;
            if (current > previous_source) {
                previous_source = current;
                progress_at = now;
            }
            if (partial_loss) {
                uint64_t captured_us = 0U, age = 0U;
                int64_t state = viewer_state(display, viewer, &captured_us);
                if (x11_frame_age(history, "/coord", state, captured_us, &age) == 0) {
                    if (age > impaired_maximum_age) impaired_maximum_age = age;
                    if (previous_viewer >= 0 && state > previous_viewer) impaired_distinct += 1U;
                    previous_viewer = state;
                }
                if (history->failed) goto failed;
            }
            if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) goto failed;
        }
        if (previous_source <= initial_source || read_connection_identity(&after) != 0 ||
            !same_connection(connection, &after)) goto failed;
        resumed_at = monotonic_millis();
        phase = "restore-network";
        if (network_profile("healthy", &after_drops, &after_packets) != 0 ||
            (strcmp(profile, "delay") == 0 ? after_packets <= before_packets
                                           : after_drops <= before_drops) ||
            (partial_loss && (after_packets <= before_packets || impaired_distinct == 0U)))
            goto failed;
        printf("FLUTTER_PEER_NETWORK_IMPAIRED_OK cycle=%u profile=%s requested_ms=%u "
               "held_ms=%llu restored_at_ms=%llu packets=%llu drops=%llu "
               "source_advanced=true stable_connection=true\n",
               cycle + 1U, profile, hold_ms,
               (unsigned long long)(resumed_at - held_from),
               (unsigned long long)resumed_at,
               after_packets - before_packets, after_drops - before_drops);
        fflush(stdout);
        if (partial_loss) {
            printf("FLUTTER_PEER_NETWORK_PARTIAL_OK cycle=%u profile=%s "
                   "displayed_distinct=%u maximum_age_ms=%llu\n", cycle + 1U,
                   profile, impaired_distinct, (unsigned long long)impaired_maximum_age);
        }
        recovery_ms = monotonic_millis() - resumed_at;
        phase = "fresh-frame-recovery";
        if (recovery_ms >= RECOVERY_LIMIT_MS ||
            wait_for_current_frames(display, viewer, history, RECOVERY_LIMIT_MS - recovery_ms,
                                    4U, &first_fresh, &recovery_age) != 0) goto failed;
        recovery_ms = monotonic_millis() - resumed_at;
        phase = "healthy-follow-up";
        if (recovery_ms > RECOVERY_LIMIT_MS ||
            inspect_viewer_candidate(display, viewer->window, pid, &same_viewer) != 1 ||
            same_viewer.window != viewer->window ||
            observe_current_frames_for_duration(source, display, viewer, history, 3000U,
                                                &max_gap, &max_age, &distinct) != 0 ||
            max_age > FRESH_LIMIT_MS || read_connection_identity(&after) != 0 ||
            !same_connection(connection, &after) ||
            read_process_resources(pid, &resources) != 0 ||
            !resources_are_bounded(baseline, &resources)) goto failed;
        print_resources("network", cycle + 1U, &resources);
        printf("FLUTTER_PEER_NETWORK_RECOVERY_OK cycle=%u recovery_ms=%llu "
               "first_fresh_ms=%llu healthy_maximum_age_ms=%llu distinct=%u "
               "same_window=true stable_connection=true resources=bounded\n", cycle + 1U,
               (unsigned long long)recovery_ms, (unsigned long long)first_fresh,
               (unsigned long long)max_age, distinct);
        fflush(stdout);
    }
    return 0;
failed:
    fprintf(stderr, "FLUTTER_PEER_X11_FAIL network phase=%s cycle=%u errno=%d\n",
            phase, cycle + 1U, errno);
    if (network_profile("healthy", &after_drops, &after_packets) != 0)
        fputs("FLUTTER_PEER_X11_FAIL network restoration; supervisor retains cleanup\n", stderr);
    return -1;
}

static int exercise_viewer_suspension(Display *source, Display *display,
                                      ViewerWindow *viewer, SourceHistory *history,
                                      unsigned long pid, const char *start,
                                      const ConnectionIdentity *connection,
                                      const ProcessResources *baseline) {
    char path[64], state = '\0';
    int process = -1, pidfd = -1, result = -1, resume_needed = 0;
    uint64_t max_gap = 0U, max_age = 0U;
    unsigned int distinct = 0U, active_cycle = 0U;
    const char *phase = "process-identity";
    struct stat metadata;
    if (start[0] < '1' || start[0] > '9' || strspn(start, "0123456789") != strlen(start) ||
        strlen(start) > 20U || pid > INT_MAX ||
        snprintf(path, sizeof(path), "/proc/%lu", pid) <= 0) goto finished;
    process = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (process < 0 || fstat(process, &metadata) != 0 || metadata.st_uid != geteuid() ||
        viewer_process_state(process, pid, start, &state) != 0 || state == 'T' || state == 't')
        goto finished;
    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0U);
    if (pidfd < 0 || !viewer_pidfd_alive(pidfd) ||
        viewer_process_state(process, pid, start, &state) != 0) goto finished;
    phase = "healthy-baseline";
    if (observe_current_frames_for_duration(source, display, viewer, history, 3000U,
                                            &max_gap, &max_age, &distinct) != 0 ||
        max_age > FRESH_LIMIT_MS) goto finished;
    printf("FLUTTER_PEER_SUSPEND_BASELINE_OK duration_ms=3000 maximum_gap_ms=%llu "
           "maximum_age_ms=%llu distinct=%u\n", (unsigned long long)max_gap,
           (unsigned long long)max_age, distinct);
    for (unsigned int cycle = 0U; cycle < FOCUS_CYCLE_COUNT; ++cycle) {
        uint64_t deadline, held_from, resumed_at, recovery_ms, first_fresh, recovery_age;
        uint64_t source_progress_at, source_max_gap = 0U;
        int64_t paused_frame, source_before, source_after;
        uint64_t captured_us = 0U;
        ConnectionIdentity after = {{0}, {0}, 0UL};
        ProcessResources resources = {0};
        ViewerWindow same_viewer = {0};
        active_cycle = cycle + 1U;
        phase = "stop";
        if (!viewer_pidfd_alive(pidfd) ||
            viewer_process_state(process, pid, start, &state) != 0 ||
            syscall(SYS_pidfd_send_signal, pidfd, SIGSTOP, NULL, 0U) != 0) goto finished;
        resume_needed = 1;
        deadline = monotonic_millis() + 1000U;
        do {
            if (viewer_process_state(process, pid, start, &state) != 0 ||
                !viewer_pidfd_alive(pidfd)) goto finished;
            if (state == 'T') break;
            if (sleep_millis(10U) != 0) goto finished;
        } while (monotonic_millis() < deadline);
        if (state != 'T' || sleep_millis(200U) != 0) goto finished;
        /* Let already-submitted X11 work finish before measuring the frozen surface. */
        paused_frame = viewer_state(display, viewer, &captured_us);
        source_before = source_state(source);
        if (paused_frame < 0 || source_before < 0) goto finished;
        held_from = monotonic_millis();
        source_progress_at = held_from;
        source_after = source_before;
        deadline = held_from + blur_hold_ms[cycle];
        phase = "frozen-pixels";
        do {
            int64_t current_source = source_state(source);
            uint64_t now = monotonic_millis();
            uint64_t source_gap = now - source_progress_at;
            if (source_gap > source_max_gap) source_max_gap = source_gap;
            if (source_gap > FRESH_LIMIT_MS ||
                (current_source >= 0 && current_source < source_after)) goto finished;
            if (current_source > source_after) {
                source_after = current_source;
                source_progress_at = now;
            }
            if (viewer_process_state(process, pid, start, &state) != 0 || state != 'T' ||
                !viewer_pidfd_alive(pidfd) ||
                viewer_state(display, viewer, &captured_us) != paused_frame ||
                sleep_millis(SAMPLE_INTERVAL_MS) != 0) goto finished;
        } while (monotonic_millis() < deadline);
        phase = "source-progress-and-connection";
        if (source_after <= source_before ||
            read_connection_identity(&after) != 0 || !same_connection(connection, &after))
            goto finished;
        printf("FLUTTER_PEER_SUSPENDED_OK cycle=%u requested_ms=%u held_ms=%llu "
               "viewer_frame=%lld source_before=%lld source_after=%lld "
               "source_maximum_gap_ms=%llu kernel_state=T "
               "pixels=frozen stable_connection=true\n", cycle + 1U, blur_hold_ms[cycle],
               (unsigned long long)(monotonic_millis() - held_from), (long long)paused_frame,
               (long long)source_before, (long long)source_after,
               (unsigned long long)source_max_gap);
        fflush(stdout);
        resumed_at = monotonic_millis();
        phase = "resume";
        if (syscall(SYS_pidfd_send_signal, pidfd, SIGCONT, NULL, 0U) != 0) goto finished;
        resume_needed = 0;
        phase = "fresh-frame-recovery";
        if (wait_for_current_frames(display, viewer, history, RECOVERY_LIMIT_MS, 4U,
                                    &first_fresh, &recovery_age) != 0) goto finished;
        recovery_ms = monotonic_millis() - resumed_at;
        phase = "healthy-follow-up-and-resources";
        if (recovery_ms > RECOVERY_LIMIT_MS ||
            inspect_viewer_candidate(display, viewer->window, pid, &same_viewer) != 1 ||
            same_viewer.window != viewer->window || !viewer_pidfd_alive(pidfd) ||
            viewer_process_state(process, pid, start, &state) != 0 || state == 'T' ||
            observe_current_frames_for_duration(source, display, viewer, history, 3000U,
                                                &max_gap, &max_age, &distinct) != 0 ||
            max_age > FRESH_LIMIT_MS || read_connection_identity(&after) != 0 ||
            !same_connection(connection, &after) ||
            read_process_resources(pid, &resources) != 0 ||
            !resources_are_bounded(baseline, &resources)) goto finished;
        print_resources("suspend", cycle + 1U, &resources);
        printf("FLUTTER_PEER_SUSPEND_RECOVERY_OK cycle=%u recovery_ms=%llu "
               "first_fresh_ms=%llu recovery_observed_maximum_age_ms=%llu "
               "healthy_ms=3000 healthy_maximum_gap_ms=%llu healthy_maximum_age_ms=%llu "
               "distinct=%u same_window=true stable_connection=true resources=bounded\n",
               cycle + 1U, (unsigned long long)recovery_ms, (unsigned long long)first_fresh,
               (unsigned long long)recovery_age, (unsigned long long)max_gap,
               (unsigned long long)max_age, distinct);
        fflush(stdout);
    }
    result = 0;
finished:
    if (result != 0) {
        fprintf(stderr, "FLUTTER_PEER_X11_FAIL suspension phase=%s cycle=%u state=%c "
                "errno=%d maximum_age_ms=%llu maximum_gap_ms=%llu distinct=%u\n",
                phase, active_cycle, state != '\0' ? state : '?', errno,
                (unsigned long long)max_age, (unsigned long long)max_gap, distinct);
    }
    if (resume_needed && syscall(SYS_pidfd_send_signal, pidfd, SIGCONT, NULL, 0U) != 0)
        fputs("FLUTTER_PEER_X11_FAIL exact viewer resume; stage retains cleanup ownership\n", stderr);
    if (pidfd >= 0 && close(pidfd) != 0) result = -1;
    if (process >= 0 && close(process) != 0) result = -1;
    return result;
}

static int write_all(int descriptor, const char *buffer, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ssize_t written = write(descriptor, buffer + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int read_exact_and_eof(int descriptor, char *buffer, size_t length) {
    size_t offset = 0U;
    char extra;
    while (offset < length) {
        ssize_t received = read(descriptor, buffer + offset, length - offset);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    for (;;) {
        ssize_t received = read(descriptor, &extra, 1U);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        return received == 0 ? 0 : -1;
    }
}

static int open_coord_root(void) {
    int descriptor = open("/coord", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat metadata;
    if (descriptor < 0) {
        return -1;
    }
    if (fstat(descriptor, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != geteuid() || metadata.st_gid != getegid() ||
        (metadata.st_mode & 0777U) != 0700U) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int request_server_restart(int coord, unsigned int generation) {
    char temporary[64];
    char request[64];
    char content[64];
    int descriptor;
    int status = 0;
    int content_length;
    int temporary_length = snprintf(temporary, sizeof(temporary),
                                    "server.restart.%u.request.tmp", generation);
    int request_length = snprintf(request, sizeof(request),
                                  "server.restart.%u.request", generation);
    if (temporary_length <= 0 || (size_t)temporary_length >= sizeof(temporary) ||
        request_length <= 0 || (size_t)request_length >= sizeof(request)) {
        return -1;
    }
    content_length = snprintf(content, sizeof(content), "generation=%u\n", generation);
    if (content_length <= 0 || (size_t)content_length >= sizeof(content)) {
        return -1;
    }
    descriptor = openat(coord, temporary,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return -1;
    }
    if (write_all(descriptor, content, (size_t)content_length) != 0 ||
        fsync(descriptor) != 0) {
        status = -1;
    }
    if (close(descriptor) != 0) {
        status = -1;
    }
    if (status != 0) {
        unlinkat(coord, temporary, 0);
        return -1;
    }
    if (renameat(coord, temporary, coord, request) != 0) {
        unlinkat(coord, temporary, 0);
        return -1;
    }
    if (fsync(coord) != 0) {
        unlinkat(coord, request, 0);
        (void)fsync(coord);
        return -1;
    }
    return 0;
}

static int wait_for_server_restart(int coord, unsigned int generation) {
    char ready[64];
    char expected[64];
    int ready_length = snprintf(ready, sizeof(ready),
                                "server.restart.%u.ready", generation);
    int expected_length = snprintf(expected, sizeof(expected), "generation=%u\n", generation);
    uint64_t deadline = monotonic_millis() + RECONNECT_LIMIT_MS;
    if (ready_length <= 0 || (size_t)ready_length >= sizeof(ready) ||
        expected_length <= 0 || (size_t)expected_length >= sizeof(expected)) {
        return -1;
    }
    while (monotonic_millis() < deadline) {
        int descriptor = openat(coord, ready, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (descriptor >= 0) {
            struct stat metadata;
            char observed[64];
            if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
                metadata.st_uid != geteuid() || metadata.st_gid != getegid() ||
                (metadata.st_mode & 0777U) != 0600U || metadata.st_nlink != 1 ||
                metadata.st_size != expected_length) {
                close(descriptor);
                return -1;
            }
            if (read_exact_and_eof(descriptor, observed, (size_t)expected_length) != 0 ||
                memcmp(observed, expected, (size_t)expected_length) != 0) {
                close(descriptor);
                return -1;
            }
            if (close(descriptor) != 0 || unlinkat(coord, ready, 0) != 0 ||
                fsync(coord) != 0) {
                return -1;
            }
            return 0;
        }
        if (errno != ENOENT || sleep_millis(SAMPLE_INTERVAL_MS) != 0) {
            return -1;
        }
    }
    return -1;
}

static Window create_focus_sink(Display *display) {
    int screen = DefaultScreen(display);
    Window root = RootWindow(display, screen);
    Window sink = XCreateSimpleWindow(display, root, 8, 8, 180U, 110U, 1U,
                                      WhitePixel(display, screen), BlackPixel(display, screen));
    if (sink == 0) {
        return 0;
    }
    XStoreName(display, sink, "rustdesk-peer-focus-sink");
    XMapRaised(display, sink);
    XSetInputFocus(display, sink, RevertToParent, CurrentTime);
    XSync(display, False);
    return sink;
}

static int return_focus_with_pointer(Display *display, const ViewerWindow *viewer) {
    Window child;
    int root_x;
    int root_y;
    XRaiseWindow(display, viewer->window);
    XSetInputFocus(display, viewer->window, RevertToParent, CurrentTime);
    if (XTranslateCoordinates(display, viewer->window,
                              RootWindow(display, DefaultScreen(display)),
                              (int)viewer->width / 2, (int)viewer->height / 2,
                              &root_x, &root_y, &child) == 0) {
        return -1;
    }
    if (XTestFakeMotionEvent(display, DefaultScreen(display), root_x, root_y, CurrentTime) == 0 ||
        XTestFakeButtonEvent(display, 1U, True, CurrentTime) == 0 ||
        XTestFakeButtonEvent(display, 1U, False, CurrentTime) == 0) {
        return -1;
    }
    XSync(display, False);
    return 0;
}

static int close_viewer(Display *display, Window window) {
    Atom protocols = XInternAtom(display, "WM_PROTOCOLS", False);
    Atom delete_window = XInternAtom(display, "WM_DELETE_WINDOW", False);
    XEvent event;
    memset(&event, 0, sizeof(event));
    event.xclient.type = ClientMessage;
    event.xclient.window = window;
    event.xclient.message_type = protocols;
    event.xclient.format = 32;
    event.xclient.data.l[0] = (long)delete_window;
    event.xclient.data.l[1] = (long)CurrentTime;
    if (XSendEvent(display, window, False, NoEventMask, &event) == 0) {
        return -1;
    }
    XSync(display, False);
    return 0;
}

static int keyboard_is_released(Display *display) {
    char keys[32];
    XQueryKeymap(display, keys);
    for (size_t i = 0U; i < sizeof(keys); ++i) {
        if (keys[i] != 0) return 0;
    }
    return 1;
}

static int keyboard_matches(Display *display, const KeyCode *codes, size_t count) {
    unsigned char expected[32] = {0};
    char actual[32];
    for (size_t i = 0U; i < count; ++i) {
        if (codes[i] < 8U) return 0;
        expected[codes[i] / 8U] |= (unsigned char)(1U << (codes[i] % 8U));
    }
    return XQueryKeymap(display, actual) != 0 && memcmp(actual, expected, sizeof(actual)) == 0;
}

static int exercise_keyboard_retirement(Display *source, Display *display,
                                        const ViewerWindow *viewer, const char *start,
                                        const ConnectionIdentity *connection) {
    const KeySym symbols[] = {XK_Control_L, XK_Shift_L};
    KeyCode remote[3] = {0}, local[2] = {0};
    Window root = RootWindow(source, DefaultScreen(source));
    char path[64], state = '\0';
    int process = -1, pidfd = -1, result = -1, foreign_held = 0;
    unsigned int local_held = 0U;
    struct stat metadata;
    uint64_t killed_at = 0U, released_at = 0U;
    const char *phase = "identity";
    if (start[0] < '1' || start[0] > '9' || strspn(start, "0123456789") != strlen(start) ||
        strlen(start) > 20U || viewer->pid > INT_MAX ||
        snprintf(path, sizeof(path), "/proc/%lu", viewer->pid) <= 0) goto finished;
    process = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (process < 0 || fstat(process, &metadata) != 0 || metadata.st_uid != geteuid() ||
        viewer_process_state(process, viewer->pid, start, &state) != 0) goto finished;
    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)viewer->pid, 0U);
    if (pidfd < 0 || !viewer_pidfd_alive(pidfd) ||
        viewer_process_state(process, viewer->pid, start, &state) != 0) goto finished;
    for (size_t i = 0U; i < 2U; ++i) {
        remote[i] = XKeysymToKeycode(source, symbols[i]);
        local[i] = XKeysymToKeycode(display, symbols[i]);
        if (remote[i] == 0U || local[i] == 0U) goto finished;
    }
    remote[2] = XKeysymToKeycode(source, XK_Control_R);
    if (remote[2] == 0U || remote[0] == remote[1] || remote[2] == remote[0] ||
        remote[2] == remote[1] || local[0] == local[1]) goto finished;
    phase = "remote-hold";
    XSelectInput(source, root, KeyPressMask | KeyReleaseMask);
    XSetInputFocus(source, root, RevertToParent, CurrentTime);
    XSync(source, False);
    if (return_focus_with_pointer(display, viewer) != 0 ||
        !keyboard_is_released(source) || !keyboard_is_released(display)) goto finished;
    for (size_t i = 0U; i < 2U; ++i) {
        if (XTestFakeKeyEvent(display, local[i], True, CurrentTime) == 0) goto finished;
        local_held += 1U;
        XSync(display, False);
        if (sleep_millis(30U) != 0) goto finished;
    }
    for (unsigned int pass = 0U; pass < 2U; ++pass) {
        unsigned int seen = 0U, events = 0U;
        uint64_t deadline = monotonic_millis() + 5000U, complete = 0U;
        while (monotonic_millis() < deadline) {
            while (XPending(source) != 0) {
                XEvent event;
                if (++events > 128U) goto finished;
                XNextEvent(source, &event);
                if (event.type == MappingNotify) {
                    XRefreshKeyboardMapping(&event.xmapping);
                    continue;
                }
                if (event.type != KeyPress && event.type != KeyRelease) continue;
                unsigned int bit = event.xkey.keycode == remote[0] ? 1U :
                                   event.xkey.keycode == remote[1] ? 2U : 0U;
                printf("FLUTTER_PEER_KEY_RETIRE_EVENT phase=%s type=%d code=%u state=%u synthetic=%d\n",
                       phase, event.type, event.xkey.keycode, event.xkey.state, event.xkey.send_event);
                if (event.xkey.window != root || event.xkey.send_event || bit == 0U ||
                    (seen & bit) != 0U || event.type != (pass == 0U ? KeyPress : KeyRelease) ||
                    (pass == 0U && bit != (seen == 0U ? 1U : 2U))) goto finished;
                seen |= bit;
                if (seen == 3U) complete = monotonic_millis();
            }
            if (complete != 0U && monotonic_millis() - complete >= 100U) break;
            if (sleep_millis(10U) != 0) goto finished;
        }
        if (seen != 3U || complete == 0U || monotonic_millis() >= deadline) goto finished;
        if (pass == 1U) {
            struct pollfd exited = {.fd = pidfd, .events = POLLIN};
            int status;
            do { status = poll(&exited, 1U, 0); } while (status < 0 && errno == EINTR);
            if (status != 1 || (exited.revents & POLLIN) == 0 ||
                (exited.revents & (POLLERR | POLLNVAL)) != 0 ||
                !keyboard_matches(source, remote + 2, 1U)) goto finished;
            released_at = complete;
            break;
        }
        ConnectionIdentity current = {{0}, {0}, 0UL};
        if (!keyboard_matches(source, remote, 2U) || !keyboard_matches(display, local, 2U) ||
            read_connection_identity(&current) != 0 || !same_connection(connection, &current))
            goto finished;
        phase = "local-hold";
        if (XTestFakeKeyEvent(source, remote[2], True, CurrentTime) == 0) goto finished;
        foreign_held = 1;
        XSync(source, False);
        unsigned int foreign_events = 0U;
        events = 0U;
        while (XPending(source) != 0) {
            XEvent event;
            if (++events > 128U) goto finished;
            XNextEvent(source, &event);
            if (event.type != KeyPress && event.type != KeyRelease) continue;
            if (++foreign_events != 1U || event.type != KeyPress || event.xkey.window != root ||
                event.xkey.send_event || event.xkey.keycode != remote[2]) goto finished;
        }
        if (foreign_events != 1U || !keyboard_matches(source, remote, 3U)) goto finished;
        puts("FLUTTER_PEER_KEY_RETIRE_HELD_OK remote_keys=2 local_keys=1 exact_native_state=true");
        phase = "abrupt-retirement";
        if (!viewer_pidfd_alive(pidfd) ||
            viewer_process_state(process, viewer->pid, start, &state) != 0) goto finished;
        killed_at = monotonic_millis();
        if (syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0U) != 0) goto finished;
    }
    if (released_at < killed_at || released_at - killed_at >= 5000U) goto finished;
    printf("FLUTTER_PEER_KEY_RETIRE_RELEASED_OK remote_keys=2 local_keys=1 elapsed_ms=%llu "
           "limit_ms=5000 native_releases=true local_preserved=true viewer_exited=true\n",
           (unsigned long long)(released_at - killed_at));
    result = 0;
finished:
    /* These fixture-owned releases occur only after the product observations above. */
    if (foreign_held && XTestFakeKeyEvent(source, remote[2], False, CurrentTime) == 0) result = -1;
    while (local_held != 0U) {
        if (XTestFakeKeyEvent(display, local[--local_held], False, CurrentTime) == 0) result = -1;
    }
    XSync(source, False);
    XSync(display, False);
    if (result == 0 && (!keyboard_is_released(source) || !keyboard_is_released(display))) result = -1;
    if (pidfd >= 0 && close(pidfd) != 0) result = -1;
    if (process >= 0 && close(process) != 0) result = -1;
    if (result != 0) fprintf(stderr, "FLUTTER_PEER_X11_FAIL key-retirement phase=%s errno=%d\n", phase, errno);
    return result;
}

static int mouse_snapshot(Display *display, int *x, int *y, unsigned int *mask) {
    Window root, child;
    int local_x, local_y;
    return XQueryPointer(display, RootWindow(display, DefaultScreen(display)),
                         &root, &child, x, y, &local_x, &local_y, mask) ? 0 : -1;
}

static int mouse_button_set_matches(Display *display, const unsigned int *held, size_t count) {
    int device;
    Window root, child;
    double root_x, root_y, win_x, win_y;
    XIButtonState buttons = {0};
    XIModifierState modifiers;
    XIGroupState group;
    if (!XIGetClientPointer(display, None, &device)) return 0;
    int matched = XIQueryPointer(display, device, RootWindow(display, DefaultScreen(display)),
        &root, &child, &root_x, &root_y, &win_x, &win_y, &buttons, &modifiers, &group);
    if (buttons.mask == NULL || buttons.mask_len < 2 || buttons.mask_len > 32) matched = 0;
    if (matched) {
        for (unsigned int i = 0U; i < (unsigned int)buttons.mask_len * 8U; ++i) {
            int expected = 0;
            for (size_t j = 0U; j < count; ++j) if (held[j] == i) expected = 1;
            if ((XIMaskIsSet(buttons.mask, i) != 0) != expected) matched = 0;
        }
        for (size_t j = 0U; j < count; ++j)
            if (held[j] == 0U || held[j] >= (unsigned int)buttons.mask_len * 8U) matched = 0;
    }
    if (buttons.mask != NULL) XFree(buttons.mask);
    return matched;
}

static int mouse_buttons_match(Display *display, unsigned int held) {
    return mouse_button_set_matches(display, &held, held == 0U ? 0U : 1U);
}

static int exercise_mouse_retirement(Display *source, Display *display,
                                     const ViewerWindow *viewer, const char *start,
                                     const ConnectionIdentity *connection) {
    const unsigned int buttons[] = {1U, 8U, 9U, 3U};
    Window root = RootWindow(source, DefaultScreen(source));
    char path[64], state = '\0';
    int process = -1, pidfd = -1, result = -1, foreign_held = 0;
    unsigned int local_held = 0U;
    struct stat metadata;
    uint64_t killed_at = 0U, released_at = 0U;
    const char *phase = "identity";
    if (start[0] < '1' || start[0] > '9' || strspn(start, "0123456789") != strlen(start) ||
        strlen(start) > 20U || viewer->pid > INT_MAX ||
        snprintf(path, sizeof(path), "/proc/%lu", viewer->pid) <= 0) goto finished;
    process = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (process < 0 || fstat(process, &metadata) != 0 || metadata.st_uid != geteuid() ||
        viewer_process_state(process, viewer->pid, start, &state) != 0) goto finished;
    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)viewer->pid, 0U);
    if (pidfd < 0 || !viewer_pidfd_alive(pidfd) ||
        viewer_process_state(process, viewer->pid, start, &state) != 0) goto finished;
    int source_major = 2, source_minor = 0, viewer_major = 2, viewer_minor = 0;
    unsigned char mapping[32];
    if (XIQueryVersion(source, &source_major, &source_minor) != Success ||
        XIQueryVersion(display, &viewer_major, &viewer_minor) != Success ||
        XGetPointerMapping(source, mapping, sizeof(mapping)) < 9) goto finished;
    for (unsigned int i = 0U; i < 9U; ++i) if (mapping[i] != i + 1U) goto finished;
    if (XGetPointerMapping(display, mapping, sizeof(mapping)) < 9) goto finished;
    for (unsigned int i = 0U; i < 9U; ++i) if (mapping[i] != i + 1U) goto finished;
    phase = "focus-click";
    if (!mouse_buttons_match(source, 0U) || !mouse_buttons_match(display, 0U)) goto finished;
    XSelectInput(source, root, ButtonPressMask | ButtonReleaseMask);
    XSync(source, False);
    if (return_focus_with_pointer(display, viewer) != 0) goto finished;
    unsigned int focus_events = 0U, focus_scans = 0U;
    uint64_t focus_deadline = monotonic_millis() + 5000U, focus_complete = 0U;
    while (monotonic_millis() < focus_deadline) {
        while (XPending(source) != 0) {
            XEvent event;
            if (++focus_scans > 128U) goto finished;
            XNextEvent(source, &event);
            if (event.type != ButtonPress && event.type != ButtonRelease) continue;
            if (focus_events >= 2U || event.xbutton.window != root || event.xbutton.send_event ||
                event.xbutton.button != 1U ||
                event.type != (focus_events == 0U ? ButtonPress : ButtonRelease) ||
                event.xbutton.state != (focus_events == 0U ? 0U : Button1Mask)) goto finished;
            if (++focus_events == 2U) focus_complete = monotonic_millis();
        }
        if (focus_complete != 0U && monotonic_millis() - focus_complete >= 100U) break;
        if (sleep_millis(10U) != 0) goto finished;
    }
    if (focus_events != 2U || focus_complete == 0U || monotonic_millis() >= focus_deadline ||
        !mouse_buttons_match(source, 0U) || !mouse_buttons_match(display, 0U)) goto finished;
    puts("FLUTTER_PEER_MOUSE_RETIRE_CONTROL_OK focus_click=delivered released=both");
    phase = "remote-hold";
    for (size_t i = 0U; i < 3U; ++i) {
        if (XTestFakeButtonEvent(display, buttons[i], True, CurrentTime) == 0) goto finished;
        local_held += 1U;
        XSync(display, False);
        if (sleep_millis(30U) != 0) goto finished;
    }
    for (unsigned int pass = 0U; pass < 2U; ++pass) {
        unsigned int seen = 0U, events = 0U;
        uint64_t deadline = monotonic_millis() + 5000U, complete = 0U;
        while (monotonic_millis() < deadline) {
            while (XPending(source) != 0) {
                XEvent event;
                if (++events > 128U) goto finished;
                XNextEvent(source, &event);
                if (event.type != ButtonPress && event.type != ButtonRelease) continue;
                unsigned int bit = event.xbutton.button == buttons[0] ? 1U :
                    event.xbutton.button == buttons[1] ? 2U :
                    event.xbutton.button == buttons[2] ? 4U : 0U;
                unsigned int expected_state = pass == 0U ? (seen == 0U ? 0U : Button1Mask) :
                    Button3Mask | ((seen & 1U) == 0U ? Button1Mask : 0U);
                printf("FLUTTER_PEER_MOUSE_RETIRE_EVENT phase=%s type=%d button=%u state=%u synthetic=%d\n",
                       phase, event.type, event.xbutton.button, event.xbutton.state, event.xbutton.send_event);
                if (event.xbutton.window != root || event.xbutton.send_event || bit == 0U ||
                    (seen & bit) != 0U || event.type != (pass == 0U ? ButtonPress : ButtonRelease) ||
                    event.xbutton.state != expected_state ||
                    (pass == 0U && bit != (seen == 0U ? 1U : seen == 1U ? 2U : 4U))) goto finished;
                seen |= bit;
                if (seen == 7U) complete = monotonic_millis();
            }
            if (complete != 0U && monotonic_millis() - complete >= 100U) break;
            if (sleep_millis(10U) != 0) goto finished;
        }
        if (seen != 7U || complete == 0U || monotonic_millis() >= deadline) goto finished;
        if (pass == 1U) {
            struct pollfd exited = {.fd = pidfd, .events = POLLIN};
            int status;
            do { status = poll(&exited, 1U, 0); } while (status < 0 && errno == EINTR);
            if (status != 1 || (exited.revents & POLLIN) == 0 ||
                (exited.revents & (POLLERR | POLLNVAL)) != 0 ||
                !mouse_button_set_matches(source, buttons + 3, 1U)) goto finished;
            released_at = complete;
            break;
        }
        ConnectionIdentity current = {{0}, {0}, 0UL};
        if (!mouse_button_set_matches(source, buttons, 3U) ||
            !mouse_button_set_matches(display, buttons, 3U) ||
            read_connection_identity(&current) != 0 || !same_connection(connection, &current)) goto finished;
        phase = "local-hold";
        if (XTestFakeButtonEvent(source, buttons[3], True, CurrentTime) == 0) goto finished;
        foreign_held = 1;
        XSync(source, False);
        unsigned int foreign_events = 0U;
        events = 0U;
        while (XPending(source) != 0) {
            XEvent event;
            if (++events > 128U) goto finished;
            XNextEvent(source, &event);
            if (event.type != ButtonPress && event.type != ButtonRelease) continue;
            if (++foreign_events != 1U || event.type != ButtonPress || event.xbutton.window != root ||
                event.xbutton.send_event || event.xbutton.button != buttons[3] ||
                event.xbutton.state != Button1Mask) goto finished;
        }
        if (foreign_events != 1U || !mouse_button_set_matches(source, buttons, 4U)) goto finished;
        puts("FLUTTER_PEER_MOUSE_RETIRE_HELD_OK remote_buttons=3 local_buttons=1 exact_native_state=true");
        phase = "abrupt-retirement";
        if (!viewer_pidfd_alive(pidfd) ||
            viewer_process_state(process, viewer->pid, start, &state) != 0) goto finished;
        killed_at = monotonic_millis();
        if (syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0U) != 0) goto finished;
    }
    if (released_at < killed_at || released_at - killed_at >= 5000U) goto finished;
    printf("FLUTTER_PEER_MOUSE_RETIRE_RELEASED_OK remote_buttons=3 local_buttons=1 elapsed_ms=%llu "
           "limit_ms=5000 native_releases=true local_preserved=true viewer_exited=true\n",
           (unsigned long long)(released_at - killed_at));
    result = 0;
finished:
    /* Fixture cleanup cannot supply any of the observed remote releases. */
    if (foreign_held && XTestFakeButtonEvent(source, buttons[3], False, CurrentTime) == 0) result = -1;
    while (local_held != 0U) {
        if (XTestFakeButtonEvent(display, buttons[--local_held], False, CurrentTime) == 0) result = -1;
    }
    XSync(source, False);
    XSync(display, False);
    if (result == 0 && (!mouse_buttons_match(source, 0U) || !mouse_buttons_match(display, 0U))) result = -1;
    XSelectInput(source, root, NoEventMask);
    XSync(source, False);
    if (pidfd >= 0 && close(pidfd) != 0) result = -1;
    if (process >= 0 && close(process) != 0) result = -1;
    if (result != 0) fprintf(stderr, "FLUTTER_PEER_X11_FAIL mouse-retirement phase=%s errno=%d\n", phase, errno);
    return result;
}

static int wait_mouse_drag(Display *source, unsigned int button, int previous_x, int previous_y,
                           int moved, int *x, int *y) {
    uint64_t deadline = monotonic_millis() + 5000U;
    unsigned int held = button <= 5U ? 1U << (button + 7U) : 0U;
    do {
        unsigned int mask;
        if (mouse_snapshot(source, x, y, &mask) != 0) return -1;
        if (mask == held && mouse_buttons_match(source, button) &&
            (!moved || (*x >= previous_x + 10 && *y >= previous_y + 10))) {
            return 0;
        }
        if (sleep_millis(10U) != 0) return -1;
    } while (monotonic_millis() < deadline);
    fprintf(stderr, "FLUTTER_PEER_X11_FAIL mouse drag button=%u previous=%d,%d actual=%d,%d\n",
            button, previous_x, previous_y, *x, *y);
    return -1;
}

static int exercise_mouse_input(Display *source, Display *display,
                                const ViewerWindow *viewer,
                                const ConnectionIdentity *connection,
                                const ProcessResources *baseline) {
    enum { MOUSE_CLICK, MOUSE_DRAG, MOUSE_EXIT, MOUSE_REENTER, MOUSE_SIDE };
    static const struct { const char *name; unsigned int button; int action; } cases[] = {
        {"left-click", 1U, MOUSE_CLICK}, {"middle-click", 2U, MOUSE_CLICK},
        {"right-click", 3U, MOUSE_CLICK}, {"left-drag", 1U, MOUSE_DRAG},
        {"wheel-up", 4U, MOUSE_CLICK}, {"wheel-down", 5U, MOUSE_CLICK},
        {"wheel-left", 6U, MOUSE_CLICK}, {"wheel-right", 7U, MOUSE_CLICK},
        {"left-release-outside", 1U, MOUSE_EXIT}, {"left-reentry", 1U, MOUSE_REENTER},
        {"middle-release-outside", 2U, MOUSE_EXIT}, {"middle-reentry", 2U, MOUSE_REENTER},
        {"right-release-outside", 3U, MOUSE_EXIT}, {"right-reentry", 3U, MOUSE_REENTER},
        {"back-click", 8U, MOUSE_SIDE}, {"forward-click", 9U, MOUSE_SIDE},
        {"left-after-side-buttons", 1U, MOUSE_CLICK},
        {"back-release-outside", 8U, MOUSE_EXIT}, {"back-reentry", 8U, MOUSE_REENTER},
        {"forward-release-outside", 9U, MOUSE_EXIT}, {"forward-reentry", 9U, MOUSE_REENTER},
    };
    Window root = RootWindow(source, DefaultScreen(source)), child;
    unsigned char mapping[32];
    int origin_x, origin_y, result = -1;
    int center_x, center_y;
    unsigned int injected_held = 0U;
    int source_major = 2, source_minor = 0, viewer_major = 2, viewer_minor = 0;
    if (XIQueryVersion(source, &source_major, &source_minor) != Success ||
        XIQueryVersion(display, &viewer_major, &viewer_minor) != Success) return -1;
    /* Admit identity button maps on both independent X servers. */
    if (XGetPointerMapping(source, mapping, sizeof(mapping)) < 9) return -1;
    for (unsigned int i = 0U; i < 9U; ++i) if (mapping[i] != i + 1U) return -1;
    if (XGetPointerMapping(display, mapping, sizeof(mapping)) < 9) return -1;
    for (unsigned int i = 0U; i < 9U; ++i) if (mapping[i] != i + 1U) return -1;
    if (return_focus_with_pointer(display, viewer) != 0 || sleep_millis(250U) != 0 ||
        !XTranslateCoordinates(display, viewer->window,
            RootWindow(display, DefaultScreen(display)),
            (int)viewer->width / 2, (int)viewer->height / 2,
            &origin_x, &origin_y, &child) ||
        mouse_snapshot(source, &center_x, &center_y, &injected_held) != 0 ||
        injected_held != 0U) return -1;
    XSelectInput(source, root, ButtonPressMask | ButtonReleaseMask | PointerMotionMask);
    XSync(source, False);

    for (unsigned int i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        unsigned int button = cases[i].button;
        unsigned int bit = button <= 5U ? 1U << (button + 7U) : 0U;
        unsigned int mask, received = 0U, events = 0U, held_moves = 0U;
        int start_x, start_y, end_x, end_y, local_x, local_y;
        int outside_x = 0, outside_y = 0;
        uint64_t start = monotonic_millis(), complete = 0U;
        ConnectionIdentity after = {{0}, {0}, 0UL};
        ProcessResources resources;
        ViewerWindow current = {0};
        if (cases[i].action == MOUSE_REENTER) {
            if (XTestFakeMotionEvent(display, DefaultScreen(display),
                                    origin_x, origin_y, CurrentTime) == 0) goto finished;
            XSync(display, False);
            do {
                if (mouse_snapshot(source, &end_x, &end_y, &mask) != 0 || mask != 0U) goto finished;
                if (end_x == center_x && end_y == center_y) break;
                if (sleep_millis(10U) != 0) goto finished;
            } while (monotonic_millis() - start < 5000U);
            if (end_x != center_x || end_y != center_y) goto finished;
        }
        if (mouse_snapshot(source, &start_x, &start_y, &mask) != 0 || mask != 0U ||
            mouse_snapshot(display, &local_x, &local_y, &mask) != 0 || mask != 0U ||
            !mouse_buttons_match(source, 0U) || !mouse_buttons_match(display, 0U)) goto finished;
        if (XTestFakeButtonEvent(display, button, True, CurrentTime) == 0) goto finished;
        injected_held = button;
        XSync(display, False);
        if (cases[i].action == MOUSE_SIDE) {
            while (!mouse_buttons_match(source, button)) {
                if (monotonic_millis() - start >= 5000U) {
                    fprintf(stderr, "FLUTTER_PEER_X11_FAIL side button=%u remote hold absent\n", button);
                    goto finished;
                }
                if (sleep_millis(10U) != 0) goto finished;
            }
            if (!mouse_buttons_match(display, button)) goto finished;
            printf("FLUTTER_PEER_MOUSE_SIDE_HELD sequence=%u button=%u native_state=both\n",
                   i + 1U, button);
        } else if (cases[i].action == MOUSE_DRAG) {
            if (wait_mouse_drag(source, button, start_x, start_y, 0, &end_x, &end_y) != 0) goto finished;
            for (int step = 1; step <= 2; ++step) {
                int previous_x = end_x, previous_y = end_y;
                if (XTestFakeMotionEvent(display, DefaultScreen(display),
                        origin_x + step * 40, origin_y + step * 30, CurrentTime) == 0) goto finished;
                XSync(display, False);
                if (wait_mouse_drag(source, button, previous_x, previous_y, 1, &end_x, &end_y) != 0) goto finished;
            }
        } else if (cases[i].action == MOUSE_EXIT) {
            XWindowAttributes attributes, root_attributes;
            int window_x, window_y;
            Window actual_root, actual_child;
            if (wait_mouse_drag(source, button, start_x, start_y, 0, &end_x, &end_y) != 0 ||
                XGetWindowAttributes(display, viewer->window, &attributes) == 0 ||
                XGetWindowAttributes(display, attributes.root, &root_attributes) == 0 ||
                !XTranslateCoordinates(display, viewer->window, attributes.root, 0, 0,
                                       &window_x, &window_y, &child)) goto finished;
            outside_x = window_x + attributes.width / 2;
            outside_y = window_y + attributes.height + 10;
            if (outside_x < 0 || outside_x >= root_attributes.width || outside_y < 0 ||
                outside_y >= root_attributes.height ||
                XTestFakeMotionEvent(display, DefaultScreen(display),
                                    outside_x, outside_y, CurrentTime) == 0) goto finished;
            XSync(display, False);
            if (!XQueryPointer(display, viewer->window, &actual_root, &actual_child,
                               &local_x, &local_y, &window_x, &window_y, &mask) ||
                local_x != outside_x || local_y != outside_y ||
                window_y < attributes.height || mask != bit ||
                !mouse_buttons_match(display, button)) goto finished;
            printf("FLUTTER_PEER_MOUSE_OUTSIDE_HELD sequence=%u button=%u viewer_x=%d viewer_y=%d "
                   "relative_y=%d window_height=%d held=%u xi_button_held=true\n", i + 1U, button,
                   outside_x, outside_y, window_y, attributes.height, mask);
        }
        if (XTestFakeButtonEvent(display, button, False, CurrentTime) == 0) goto finished;
        injected_held = 0U;
        XSync(display, False);
        while (monotonic_millis() - start < 5000U) {
            while (XPending(source) != 0) {
                XEvent event;
                if (++events > 128U) goto finished;
                XNextEvent(source, &event);
                if (event.type == MotionNotify) {
                    unsigned int expected = received == 1U ? bit : 0U;
                    if (event.xmotion.window != root || event.xmotion.send_event ||
                        event.xmotion.state != expected) goto finished;
                    if (received == 1U) ++held_moves;
                    continue;
                }
                if (event.type != ButtonPress && event.type != ButtonRelease) continue;
                printf("FLUTTER_PEER_MOUSE_EVENT case=%u event=%u type=%d button=%u "
                       "state=%u x=%d y=%d synthetic=%d\n", i + 1U, received + 1U,
                       event.type, event.xbutton.button, event.xbutton.state,
                       event.xbutton.x_root, event.xbutton.y_root, event.xbutton.send_event);
                if (received >= 2U || event.xbutton.window != root || event.xbutton.send_event ||
                    event.xbutton.button != button ||
                    event.type != (received == 0U ? ButtonPress : ButtonRelease) ||
                    event.xbutton.state != (received == 0U ? 0U : bit)) goto finished;
                if (received == 0U || cases[i].action == MOUSE_CLICK ||
                    cases[i].action == MOUSE_REENTER || cases[i].action == MOUSE_SIDE) {
                    if (event.xbutton.x_root != start_x || event.xbutton.y_root != start_y) goto finished;
                } else if (cases[i].action == MOUSE_DRAG &&
                           (event.xbutton.x_root != end_x || event.xbutton.y_root != end_y)) goto finished;
                if (++received == 2U) complete = monotonic_millis();
            }
            if (complete != 0U && monotonic_millis() - complete >= 100U) break;
            if (sleep_millis(10U) != 0) goto finished;
        }
        if (received != 2U || complete == 0U || monotonic_millis() - start >= 5000U ||
            (cases[i].action == MOUSE_DRAG && held_moves < 2U) ||
            mouse_snapshot(source, &end_x, &end_y, &mask) != 0 || mask != 0U ||
            mouse_snapshot(display, &local_x, &local_y, &mask) != 0 || mask != 0U ||
            !mouse_buttons_match(source, 0U) || !mouse_buttons_match(display, 0U) ||
            (cases[i].action == MOUSE_EXIT && (local_x != outside_x || local_y != outside_y)) ||
            find_viewer_window(display, viewer->pid, &current) != 0 || current.window != viewer->window ||
            read_connection_identity(&after) != 0 || !same_connection(connection, &after) ||
            read_process_resources(viewer->pid, &resources) != 0 ||
            !resources_are_bounded(baseline, &resources)) {
            fprintf(stderr, "FLUTTER_PEER_X11_FAIL mouse case=%u name=%s received=%u held_moves=%u\n",
                    i + 1U, cases[i].name, received, held_moves);
            goto finished;
        }
        print_resources("mouse", i + 1U, &resources);
        printf("FLUTTER_PEER_MOUSE_CASE_OK sequence=%u name=%s events=%u held_moves=%u "
               "elapsed_ms=%llu released=both stable_connection=true\n", i + 1U,
               cases[i].name, received, held_moves, (unsigned long long)(complete - start));
        fflush(stdout);
    }
    result = 0;
finished:
    /* Retire only fixture-injected viewer input; never manufacture controlled-side releases. */
    if (injected_held != 0U) {
        if (XTestFakeButtonEvent(display, injected_held, False, CurrentTime) == 0) result = -1;
        XSync(display, False);
    }
    XSelectInput(source, root, NoEventMask);
    XSync(source, False);
    return result;
}

static int exercise_keyboard_input(Display *source, Display *display,
                                   const ViewerWindow *viewer,
                                   const ConnectionIdentity *connection,
                                   const ProcessResources *baseline) {
    static const struct {
        const char *name;
        KeySym input, modifier, output;
        unsigned int mask;
        const char *text;
    } cases[] = {
        {"letter", XK_a, NoSymbol, XK_a, 0U, "a"},
        {"shift-letter", XK_a, XK_Shift_L, XK_A, ShiftMask, "A"},
        {"digit", XK_1, NoSymbol, XK_1, 0U, "1"},
        {"shift-punctuation", XK_1, XK_Shift_L, XK_exclam, ShiftMask, "!"},
        {"space", XK_space, NoSymbol, XK_space, 0U, " "},
        {"return", XK_Return, NoSymbol, XK_Return, 0U, "\r"},
        {"backspace", XK_BackSpace, NoSymbol, XK_BackSpace, 0U, "\b"},
        {"left", XK_Left, NoSymbol, XK_Left, 0U, ""},
        {"right", XK_Right, NoSymbol, XK_Right, 0U, ""},
        {"control-letter", XK_a, XK_Control_L, XK_a, ControlMask, "\001"},
        {"after-control", XK_z, NoSymbol, XK_z, 0U, "z"},
    };
    Window root = RootWindow(source, DefaultScreen(source));
    /* The source fixture selects no keys, so native events propagate to this root sink. */
    XSelectInput(source, root, KeyPressMask | KeyReleaseMask);
    XSetInputFocus(source, root, RevertToParent, CurrentTime);
    XSync(source, False);
    if (return_focus_with_pointer(display, viewer) != 0 ||
        !keyboard_is_released(source) || !keyboard_is_released(display)) return -1;

    for (unsigned int i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        KeyCode modifier = cases[i].modifier == NoSymbol ? 0U :
                           XKeysymToKeycode(display, cases[i].modifier);
        KeyCode key = XKeysymToKeycode(display, cases[i].input);
        unsigned int expected = modifier == 0U ? 2U : 4U, received = 0U, events = 0U;
        unsigned int native_key = 0U, native_modifier = 0U;
        uint64_t start = monotonic_millis(), complete = 0U;
        ConnectionIdentity after = {{0}, {0}, 0UL};
        ProcessResources resources;
        ViewerWindow current = {0};
        Window focus;
        int revert;
        if (key == 0U || (cases[i].modifier != NoSymbol && modifier == 0U)) return -1;
        if (modifier != 0U) {
            if (XTestFakeKeyEvent(display, modifier, True, CurrentTime) == 0) return -1;
            XSync(display, False);
            if (sleep_millis(30U) != 0) return -1;
        }
        int sent = XTestFakeKeyEvent(display, key, True, CurrentTime) != 0 &&
                   XTestFakeKeyEvent(display, key, False, CurrentTime) != 0;
        XSync(display, False);
        if (modifier != 0U) {
            if (sleep_millis(30U) != 0) sent = 0;
            if (XTestFakeKeyEvent(display, modifier, False, CurrentTime) == 0) sent = 0;
            XSync(display, False);
        }
        if (!sent) return -1;
        while (monotonic_millis() - start < 5000U) {
            while (XPending(source) != 0) {
                XEvent event;
                if (++events > 128U) return -1;
                XNextEvent(source, &event);
                if (event.type == MappingNotify) {
                    XRefreshKeyboardMapping(&event.xmapping);
                    continue;
                }
                if (event.type != KeyPress && event.type != KeyRelease) continue;
                KeySym symbol = NoSymbol;
                char text[16];
                int size = XLookupString(&event.xkey, text, sizeof(text), &symbol, NULL);
                int modifier_event = modifier != 0U && (received == 0U || received == 3U);
                unsigned int position = received - (modifier != 0U ? 1U : 0U);
                int type = modifier_event ? (received == 0U ? KeyPress : KeyRelease) :
                                           (position == 0U ? KeyPress : KeyRelease);
                KeySym wanted = modifier_event ? cases[i].modifier : cases[i].output;
                unsigned int mask = modifier_event && received == 0U ? 0U : cases[i].mask;
                const char *wanted_text = modifier_event ? "" : cases[i].text;
                printf("FLUTTER_PEER_KEY_EVENT case=%u event=%u type=%d code=%u symbol=%lu "
                       "state=%u bytes=%d synthetic=%d\n", i + 1U, received + 1U,
                       event.type, event.xkey.keycode, (unsigned long)symbol,
                       event.xkey.state, size, event.xkey.send_event);
                if (received >= expected || event.xkey.window != root || event.xkey.send_event ||
                    event.type != type || symbol != wanted ||
                    (event.xkey.state & 255U) != mask || size < 0 ||
                    (size_t)size != strlen(wanted_text) ||
                    memcmp(text, wanted_text, (size_t)size) != 0) return -1;
                unsigned int *native_code = modifier_event ? &native_modifier : &native_key;
                if (type == KeyPress) *native_code = event.xkey.keycode;
                else if (*native_code == 0U || *native_code != event.xkey.keycode) return -1;
                received += 1U;
                if (received == expected) complete = monotonic_millis();
            }
            /* A quiet interval also rejects a duplicate pair after the expected release. */
            if (complete != 0U && monotonic_millis() - complete >= 100U) break;
            if (sleep_millis(10U) != 0) return -1;
        }
        XGetInputFocus(source, &focus, &revert);
        if (received != expected || complete == 0U || monotonic_millis() - start >= 5000U ||
            focus != root || !keyboard_is_released(source) || !keyboard_is_released(display) ||
            find_viewer_window(display, viewer->pid, &current) != 0 ||
            current.window != viewer->window || read_connection_identity(&after) != 0 ||
            !same_connection(connection, &after) ||
            read_process_resources(viewer->pid, &resources) != 0 ||
            !resources_are_bounded(baseline, &resources)) {
            fprintf(stderr, "FLUTTER_PEER_X11_FAIL keyboard case=%u name=%s received=%u expected=%u\n",
                    i + 1U, cases[i].name, received, expected);
            return -1;
        }
        print_resources("keyboard", i + 1U, &resources);
        printf("FLUTTER_PEER_KEYBOARD_CASE_OK sequence=%u name=%s events=%u elapsed_ms=%llu "
               "native_pair=true exact_text=true released=both stable_connection=true\n",
               i + 1U, cases[i].name, received, (unsigned long long)(complete - start));
        fflush(stdout);
    }
    XSelectInput(source, root, NoEventMask);
    XSync(source, False);
    return 0;
}

static int find_main_window(Display *display, unsigned long expected_pid, Window *window) {
    Window root = RootWindow(display, DefaultScreen(display));
    Atom net_name = XInternAtom(display, "_NET_WM_NAME", False);
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    *window = None;
    while (monotonic_millis() < deadline) {
        Window returned_root, returned_parent, *children = NULL;
        unsigned int count = 0U, matches = 0U;
        if (XQueryTree(display, root, &returned_root, &returned_parent, &children, &count) == 0) {
            return -1;
        }
        if (count > ACCESSIBLE_CHILD_LIMIT) {
            if (children != NULL) XFree(children);
            return -1;
        }
        for (unsigned int index = 0U; index < count; ++index) {
            XWindowAttributes attributes;
            XClassHint hint = {0};
            unsigned long pid;
            char title[512];
            if (read_window_pid(display, children[index], &pid) != 0 || pid != expected_pid ||
                XGetWindowAttributes(display, children[index], &attributes) == 0 ||
                attributes.map_state != IsViewable || attributes.width < 320 ||
                attributes.height < 40 ||
                read_text_property(display, children[index], net_name, title, sizeof(title)) != 0 ||
                strcmp(title, "RustDesk") != 0) continue;
            if (XGetClassHint(display, children[index], &hint) != 0 &&
                hint.res_name != NULL && hint.res_class != NULL &&
                strcmp(hint.res_name, "rustdesk") == 0 && strcmp(hint.res_class, "Rustdesk") == 0) {
                *window = children[index];
                matches += 1U;
            }
            if (hint.res_name != NULL) XFree(hint.res_name);
            if (hint.res_class != NULL) XFree(hint.res_class);
        }
        if (children != NULL) XFree(children);
        if (matches > 1U) return -1;
        if (matches == 1U) return monotonic_millis() < deadline ? 0 : -1;
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) return -1;
    }
    return -1;
}

static int main_header_luminance(Display *display, Window window, unsigned int *luminance) {
    Window root = RootWindow(display, DefaultScreen(display)), child;
    XWindowAttributes attributes;
    XImage *image;
    int x, y;
    unsigned int total = 0U;
    if (XGetWindowAttributes(display, window, &attributes) == 0 ||
        attributes.map_state != IsViewable || attributes.width < 320 || attributes.height < 40 ||
        XTranslateCoordinates(display, window, root, 40, 8, &x, &y, &child) == 0 ||
        x < 0 || y < 0 || x + 128 > DisplayWidth(display, DefaultScreen(display)) ||
        y + 16 > DisplayHeight(display, DefaultScreen(display))) return -1;
    image = XGetImage(display, root, x, y, 128U, 16U, AllPlanes, ZPixmap);
    if (image == NULL) return -1;
    for (int row = 0; row < 16; ++row) {
        for (int column = 0; column < 128; ++column) {
            unsigned long pixel = XGetPixel(image, column, row);
            total += (55U * x11_frame_component(pixel, image->red_mask) +
                      182U * x11_frame_component(pixel, image->green_mask) +
                      19U * x11_frame_component(pixel, image->blue_mask)) / 256U;
        }
    }
    XDestroyImage(image);
    *luminance = total / (128U * 16U);
    return 0;
}

static int activate_header_control(Display *display, Window window, unsigned int expected_pid,
                                     const char *tooltip) {
    XWindowAttributes attributes;
    Window child;
    unsigned long pid;
    int x, y;
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    if (read_window_pid(display, window, &pid) != 0 || pid != expected_pid ||
        XGetWindowAttributes(display, window, &attributes) == 0 ||
        attributes.map_state != IsViewable || attributes.width < 320 || attributes.height < 40 ||
        /* WindowActionPanel: three 27-pixel window buttons follow the 27-pixel tail action. */
        XTranslateCoordinates(display, window, RootWindow(display, DefaultScreen(display)),
                              attributes.width - 94, 14, &x, &y, &child) == 0 ||
        x < 0 || y < 0 || x >= DisplayWidth(display, DefaultScreen(display)) ||
        y >= DisplayHeight(display, DefaultScreen(display))) return -1;
    XRaiseWindow(display, window);
    XSetInputFocus(display, window, RevertToParent, CurrentTime);
    if (XTestFakeMotionEvent(display, DefaultScreen(display), x, y, CurrentTime) == 0) return -1;
    XSync(display, False);
    while (monotonic_millis() < deadline) {
        AtspiAccessible *label = NULL;
        if (query_named_accessible(expected_pid, tooltip, deadline, &label, 0) != 0) return -1;
        if (label != NULL) {
            g_object_unref(label);
            if (XTestFakeButtonEvent(display, 1U, True, CurrentTime) == 0 ||
                XTestFakeButtonEvent(display, 1U, False, CurrentTime) == 0) return -1;
            XSync(display, False);
            printf("FLUTTER_PEER_HEADER_ACTIVATION control=\"%s\" visible_tooltip=true "
                   "native_pointer=true\n", tooltip);
            fflush(stdout);
            return monotonic_millis() < deadline ? 0 : -1;
        }
        if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) return -1;
    }
    fprintf(stderr, "FLUTTER_PEER_X11_FAIL actual header tooltip unavailable control=\"%s\"\n",
            tooltip);
    return -1;
}

static int activate_dark_theme(Display *display, Window main, unsigned int expected_pid) {
    XWindowAttributes attributes;
    Window child;
    unsigned long pid;
    int x, y;
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    if (read_window_pid(display, main, &pid) != 0 || pid != expected_pid ||
        XGetWindowAttributes(display, main, &attributes) == 0 ||
        attributes.map_state != IsViewable ||
        XTranslateCoordinates(display, main, RootWindow(display, DefaultScreen(display)),
                              0, 0, &x, &y, &child) == 0) return -1;
    while (monotonic_millis() < deadline) {
        AtspiAccessible *label = NULL;
        AtspiComponent *component;
        AtspiRect *rect;
        GError *error = NULL;
        int valid;
        if (query_named_accessible(expected_pid, "Dark", deadline, &label, 0) != 0) return -1;
        if (label == NULL) {
            if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) return -1;
            continue;
        }
        component = atspi_accessible_get_component_iface(label);
        g_object_unref(label);
        if (component == NULL) return -1;
        rect = atspi_component_get_extents(component, ATSPI_COORD_TYPE_SCREEN, &error);
        g_object_unref(component);
        valid = error == NULL && rect != NULL && rect->width > 0 && rect->height > 0 &&
                rect->x >= x && rect->y >= y &&
                (int64_t)rect->x + rect->width <= (int64_t)x + attributes.width &&
                (int64_t)rect->y + rect->height <= (int64_t)y + attributes.height &&
                rect->x >= 0 && rect->y >= 0 &&
                (int64_t)rect->x + rect->width <= DisplayWidth(display, DefaultScreen(display)) &&
                (int64_t)rect->y + rect->height <= DisplayHeight(display, DefaultScreen(display));
        if (valid != 0 && monotonic_millis() < deadline) {
            valid = XTestFakeMotionEvent(display, DefaultScreen(display),
                                        rect->x + rect->width / 2, rect->y + rect->height / 2,
                                        CurrentTime) != 0 &&
                    XTestFakeButtonEvent(display, 1U, True, CurrentTime) != 0 &&
                    XTestFakeButtonEvent(display, 1U, False, CurrentTime) != 0;
            XSync(display, False);
        } else {
            valid = 0;
        }
        if (error != NULL) g_error_free(error);
        if (rect != NULL) g_boxed_free(ATSPI_TYPE_RECT, rect);
        return valid != 0 && monotonic_millis() < deadline ? 0 : -1;
    }
    fputs("FLUTTER_PEER_X11_FAIL actual Dark theme label unavailable\n", stderr);
    return -1;
}

static int prepare_main_settings(Display *display, const ViewerWindow *viewer, Window *main) {
    if (activate_header_control(display, viewer->window, (unsigned int)viewer->pid,
                                "New connection") != 0 ||
        find_main_window(display, viewer->pid, main) != 0 ||
        activate_header_control(display, *main, (unsigned int)viewer->pid, "Settings") != 0) {
        fputs("FLUTTER_PEER_X11_FAIL actual main settings disclosure unavailable\n", stderr);
        return -1;
    }
    XRaiseWindow(display, viewer->window);
    XSetInputFocus(display, viewer->window, RevertToParent, CurrentTime);
    XSync(display, False);
    return 0;
}

static int exercise_dialog_theme(Display *display, const ViewerWindow *viewer, Window main,
                                  AtspiAccessible *caption, const ConnectionIdentity *connection) {
    ConnectionIdentity after = {{0}, {0}, 0UL};
    unsigned int light = 0U, dark = 0U;
    uint64_t deadline;
    int status = -1;
    XRaiseWindow(display, main);
    XSetInputFocus(display, main, RevertToParent, CurrentTime);
    XSync(display, False);
    if (require_same_dialog((unsigned int)viewer->pid, caption) != 0) goto out;
    if (main_header_luminance(display, main, &light) != 0 || light < 160U) {
        fprintf(stderr, "FLUTTER_PEER_X11_FAIL main light-theme baseline unavailable luminance=%u\n",
                light);
        goto out;
    }
    puts("FLUTTER_PEER_DIALOG_THEME_BEGIN source=actual_main_settings dialog=trackpad_speed");
    fflush(stdout);
    if (activate_dark_theme(display, main, (unsigned int)viewer->pid) != 0) goto out;
    deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    while (monotonic_millis() < deadline) {
        if (main_header_luminance(display, main, &dark) != 0) goto out;
        if (dark + 64U <= light) break;
        if (sleep_millis(SAMPLE_INTERVAL_MS) != 0) goto out;
    }
    if (monotonic_millis() >= deadline || dark + 64U > light) {
        fputs("FLUTTER_PEER_X11_FAIL actual main theme change was not visible\n", stderr);
        goto out;
    }
    printf("FLUTTER_PEER_THEME_CHANGED source=actual_main_settings light_luminance=%u "
           "dark_luminance=%u native_pixels=true\n", light, dark);
    fflush(stdout);
    if (read_connection_identity(&after) != 0 || same_connection(connection, &after) == 0) {
        fputs("FLUTTER_PEER_X11_FAIL theme change replaced authenticated TCP connection\n", stderr);
        goto out;
    }
    if (require_same_dialog((unsigned int)viewer->pid, caption) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL actual theme change retired or replaced remote dialog "
              "stable_connection=true\n", stderr);
        goto out;
    }
    puts("FLUTTER_PEER_DIALOG_THEME_OK source=actual_main_settings same_accessible=true "
         "stable_connection=true");
    status = 0;
out:
    XRaiseWindow(display, viewer->window);
    XSetInputFocus(display, viewer->window, RevertToParent, CurrentTime);
    XSync(display, False);
    return status;
}

static int exercise_screenshot_save_unavailable(const ViewerWindow *viewer,
                                                const ConnectionIdentity *connection,
                                                const ProcessResources *baseline) {
    static const char missing_picker[] =
        "Exception: Couldn't find the executable zenity in the path.";
    uint64_t deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    AtspiAccessible *show = NULL, *hide = NULL, *error_text = NULL;
    ConnectionIdentity after = {{0}, {0}, 0UL};
    ProcessResources resources = {0};
    int result = -1;

    if (query_named_accessible((unsigned int)viewer->pid, "Show toolbar", deadline, &show, 0) != 0 ||
        query_named_accessible((unsigned int)viewer->pid, "Hide toolbar", deadline, &hide, 0) != 0 ||
        (show == NULL) == (hide == NULL)) goto out;
    if (show != NULL && activate_named_control((unsigned int)viewer->pid, "Show toolbar") != 0)
        goto out;
    if (activate_named_control((unsigned int)viewer->pid, "Control actions") != 0 ||
        activate_named_control((unsigned int)viewer->pid, "Take screenshot") != 0 ||
        activate_named_control((unsigned int)viewer->pid, "Save as...") != 0) goto out;
    puts("FLUTTER_PEER_SCREENSHOT_RESPONSE_OBSERVED actions=visible save_as=activated");
    fflush(stdout);

    deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
    while (monotonic_millis() < deadline && error_text == NULL) {
        /* Replaced dialog nodes can invalidate a read; only a complete peer-bound scan counts. */
        if (query_accessible((unsigned int)viewer->pid, missing_picker,
                             deadline, &error_text, 1, 1) != 0)
            g_clear_object(&error_text);
        if (error_text == NULL && sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) goto out;
    }
    if (error_text == NULL || monotonic_millis() >= deadline ||
        read_connection_identity(&after) != 0 || !same_connection(connection, &after) ||
        read_process_resources(viewer->pid, &resources) != 0 ||
        !resources_are_bounded(baseline, &resources)) goto out;
    print_resources("screenshot-save-unavailable", 1U, &resources);
    puts("FLUTTER_PEER_SCREENSHOT_SAVE_ERROR_OBSERVED helper=zenity error=visible "
         "screenshot_actions=received saved_file=unproved");
    result = 0;
out:
    if (show != NULL) g_object_unref(show);
    if (hide != NULL) g_object_unref(hide);
    if (error_text != NULL) g_object_unref(error_text);
    if (result != 0) {
        PasswordPromptScan diagnostic;
        fputs("FLUTTER_PEER_X11_FAIL screenshot missing-picker scenario\n", stderr);
        if (scan_password_prompt((unsigned int)viewer->pid, &diagnostic, 1) != 0)
            fputs("FLUTTER_PEER_X11_FAIL screenshot accessibility diagnostic\n", stderr);
    }
    return result;
}

static int exercise_dialog_resize(Display *display, ViewerWindow *viewer,
                                    const ConnectionIdentity *connection,
                                    AtspiAccessible *previous_caption) {
    const unsigned int widths[] = {1100U, 1200U, viewer->width};
    const unsigned int heights[] = {650U, 700U, viewer->height};
    Window main = None;
    AtspiAccessible *caption = NULL;
    uint64_t deadline;
    int caption_x, caption_y;
    ConnectionIdentity after = {{0}, {0}, 0UL};
    int status = -1;

    puts("FLUTTER_PEER_DIALOG_RESIZE_BEGIN dialog=trackpad_speed source=actual_toolbar");
    fflush(stdout);
    /* The real Alert hides preceding semantics, including the remote header controls. */
    if (prepare_main_settings(display, viewer, &main) != 0) goto out;
    if (open_trackpad_dialog((unsigned int)viewer->pid, &caption) != 0) goto out;
    if (previous_caption == NULL || caption == previous_caption) {
        fputs("FLUTTER_PEER_X11_FAIL reconnect did not allow a distinct new dialog\n", stderr);
        goto out;
    }
    puts("FLUTTER_PEER_DIALOG_RECREATED previous_retained=true distinct_accessible=true");
    if (read_control_position(caption, &caption_x, &caption_y) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL actual dialog layout unavailable\n", stderr);
        goto out;
    }
    puts("FLUTTER_PEER_DIALOG_READY dialog=trackpad_speed native_accessible=true");
    fflush(stdout);
    for (unsigned int resize = 0U; resize < 3U; ++resize) {
        XWindowAttributes attributes;
        int layout_changed = 0;
        int current_x = caption_x, current_y = caption_y;
        XResizeWindow(display, viewer->window, widths[resize], heights[resize]);
        XSync(display, False);
        if (XGetWindowAttributes(display, viewer->window, &attributes) == 0 ||
            attributes.map_state != IsViewable || attributes.width != (int)widths[resize] ||
            attributes.height != (int)heights[resize]) {
            fputs("FLUTTER_PEER_X11_FAIL actual window resize was not observed\n", stderr);
            goto out;
        }
        deadline = monotonic_millis() + DIALOG_CONTROL_WAIT_MS;
        while (monotonic_millis() < deadline) {
            AtspiAccessible *actual = NULL;
            int query_status = query_dialog_caption((unsigned int)viewer->pid, deadline, &actual);
            int same = actual == caption;
            int present = actual != NULL;
            if (actual != NULL) g_object_unref(actual);
            if (query_status != 0 || same == 0) {
                fprintf(stderr, "FLUTTER_PEER_X11_FAIL resize=%u dialog_observation=%s\n",
                        resize + 1U, query_status != 0 ? "unavailable" :
                        present != 0 ? "replaced" : "absent");
                goto out;
            }
            if (read_control_position(caption, &current_x, &current_y) != 0) {
                fprintf(stderr, "FLUTTER_PEER_X11_FAIL resize=%u native_layout=unavailable\n",
                        resize + 1U);
                goto out;
            }
            if (current_x != caption_x || current_y != caption_y) {
                layout_changed = 1;
                break;
            }
            if (sleep_millis(PASSWORD_PROMPT_SCAN_INTERVAL_MS) != 0) break;
        }
        if (layout_changed == 0 || monotonic_millis() >= deadline ||
            require_same_dialog((unsigned int)viewer->pid, caption) != 0) {
            fprintf(stderr, "FLUTTER_PEER_X11_FAIL resize=%u layout_changed=%d "
                    "deadline_expired=%d dialog_layout_identity_check=failed\n",
                    resize + 1U, layout_changed, monotonic_millis() >= deadline);
            goto out;
        }
        caption_x = current_x;
        caption_y = current_y;
        printf("FLUTTER_PEER_DIALOG_RESIZE_OK sequence=%u dimensions=%ux%u "
               "same_accessible=true native_layout_changed=true\n",
               resize + 1U, widths[resize], heights[resize]);
        fflush(stdout);
    }
    if (exercise_dialog_theme(display, viewer, main, caption, connection) != 0 ||
        fake_key(display, XK_Escape) != 0) goto out;
    if (wait_for_dialog_retirement((unsigned int)viewer->pid) != 0 ||
        read_connection_identity(&after) != 0 ||
        same_connection(connection, &after) == 0) goto out;
    puts("FLUTTER_PEER_DIALOG_RESIZE_TRANSACTION_OK resizes=3 same_accessible=true explicit_escape=true "
         "stable_connection=true");
    status = 0;
out:
    if (main != None && close_viewer(display, main) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL main settings window retirement\n", stderr);
        status = -1;
    }
    if (caption != NULL) g_object_unref(caption);
    if (status != 0) {
        PasswordPromptScan diagnostic;
        fputs("FLUTTER_PEER_X11_FAIL native dialog resize transaction aborted\n", stderr);
        if (scan_password_prompt((unsigned int)viewer->pid, &diagnostic, 1) != 0) {
            fputs("FLUTTER_PEER_X11_FAIL dialog accessibility diagnostic unavailable\n", stderr);
        }
    }
    return status;
}

int main(int argc, char **argv) {
    const char *source_name;
    const char *viewer_name;
    char *end = NULL;
    unsigned long viewer_pid;
    Display *source;
    Display *display;
    int event_base;
    int error_base;
    int major;
    int minor;
    ViewerWindow viewer = {0};
    SourceHistory history = {0};
    ProcessResources baseline_resources = {0};
    ProcessResources current_resources = {0};
    int coord = -1;
    uint64_t initial_fresh_ms;
    uint64_t initial_max_age;
    ConnectionIdentity current_connection = {{0}, {0}, 0UL};
    PasswordPromptScan prompt_scan = {0};
    AtspiAccessible *previous_caption = NULL;

    if (argc != 5 && (argc != 6 || (strcmp(argv[5], "--viewer-suspend") != 0 &&
                                    strcmp(argv[5], "--keyboard-retirement") != 0 &&
                                    strcmp(argv[5], "--keyboard-input") != 0 &&
                                    strcmp(argv[5], "--mouse-input") != 0 &&
                                    strcmp(argv[5], "--mouse-retirement") != 0 &&
                                    strcmp(argv[5], "--screenshot-save-unavailable") != 0 &&
                                    strcmp(argv[5], "--clipboard-text") != 0 &&
                                    strcmp(argv[5], "--clipboard-images") != 0 &&
                                    strcmp(argv[5], "--network-impairment") != 0 &&
                                    strcmp(argv[5], "--network-loss") != 0))) {
        fputs("usage: flutter-peer-presentation-x11 SOURCE_DISPLAY VIEWER_DISPLAY VIEWER_PID "
              "VIEWER_START [--viewer-suspend|--network-impairment|--network-loss|--clipboard-text|--clipboard-images|--keyboard-input|--keyboard-retirement|--mouse-input|--mouse-retirement|--screenshot-save-unavailable]\n",
              stderr);
        return 2;
    }
    source_name = argv[1];
    viewer_name = argv[2];
    errno = 0;
    viewer_pid = strtoul(argv[3], &end, 10);
    if (errno != 0 || end == argv[3] || *end != '\0' || viewer_pid == 0UL ||
        viewer_pid > UINT_MAX) {
        fputs("FLUTTER_PEER_X11_FAIL invalid viewer pid\n", stderr);
        return 2;
    }
    source = XOpenDisplay(source_name);
    display = XOpenDisplay(viewer_name);
    if (source == NULL || display == NULL) {
        fputs("FLUTTER_PEER_X11_FAIL source or viewer display unavailable\n", stderr);
        if (source != NULL) {
            XCloseDisplay(source);
        }
        if (display != NULL) {
            XCloseDisplay(display);
        }
        return 1;
    }
    if (XTestQueryExtension(display, &event_base, &error_base, &major, &minor) == 0) {
        fputs("FLUTTER_PEER_X11_FAIL XTEST unavailable\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }

    if (find_viewer_window(display, viewer_pid, &viewer) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL exact remote window unavailable\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_WINDOW_OK pid=%lu title=%s wm_instance=%s wm_class=%s dimensions=%ux%u\n",
           viewer.pid, viewer.title, viewer.instance_name, viewer.class_name, viewer.width,
           viewer.height);
    XRaiseWindow(display, viewer.window);
    XSetInputFocus(display, viewer.window, RevertToParent, CurrentTime);
    XSync(display, False);
    if (atspi_init() != 0) {
        fputs("FLUTTER_PEER_X11_FAIL private AT-SPI initialization\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    atspi_set_timeout(1000, 1000);
    if (wait_for_password_prompt((unsigned int)viewer_pid, &prompt_scan) != 0) {
        PasswordPromptScan diagnostic_scan;
        fprintf(stderr,
                "FLUTTER_PEER_X11_FAIL exact password accessible unavailable "
                "applications=%u nodes=%u password_nodes=%u visible_passwords=%u "
                "ready_passwords=%u focused_nodes=%u first_focused_role=%d "
                "first_password_states=editable:%d,enabled:%d,sensitive:%d,visible:%d,"
                "focusable:%d,focused:%d characters:%d\n",
                prompt_scan.application_roots, prompt_scan.nodes, prompt_scan.password_nodes,
                prompt_scan.visible_passwords, prompt_scan.ready_passwords,
                prompt_scan.focused_nodes, (int)prompt_scan.first_focused_role,
                prompt_scan.first_password_editable, prompt_scan.first_password_enabled,
                prompt_scan.first_password_sensitive, prompt_scan.first_password_visible,
                prompt_scan.first_password_focusable, prompt_scan.first_password_focused,
                prompt_scan.first_password_character_count);
        if (scan_password_prompt((unsigned int)viewer_pid, &diagnostic_scan, 1) != 0) {
            fputs("FLUTTER_PEER_X11_FAIL accessibility tree diagnostic unavailable\n", stderr);
        }
        exit_atspi_after_failure();
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_PASSWORD_PROMPT_READY pid=%lu applications=%u nodes=%u "
           "role=password_text editable=true enabled=true sensitive=true visible=true "
           "focusable=true focused=true characters=0\n",
           viewer_pid, prompt_scan.application_roots, prompt_scan.nodes);
    if (type_password(display) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL real password prompt input\n", stderr);
        exit_atspi_after_failure();
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (wait_for_password_character_count((unsigned int)viewer_pid,
                                          (gint)(sizeof(test_password) - 1U),
                                          &prompt_scan) != 0) {
        fprintf(stderr,
                "FLUTTER_PEER_X11_FAIL password input was not complete "
                "applications=%u nodes=%u password_nodes=%u visible_passwords=%u "
                "ready_passwords=%u characters=%d expected=%zu\n",
                prompt_scan.application_roots, prompt_scan.nodes, prompt_scan.password_nodes,
                prompt_scan.visible_passwords, prompt_scan.ready_passwords,
                prompt_scan.first_password_character_count, sizeof(test_password) - 1U);
        exit_atspi_after_failure();
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_PASSWORD_INPUT_OK characters=%zu observed_without_value=true\n",
           sizeof(test_password) - 1U);
    if (fake_key(display, XK_Return) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL real password prompt submission\n", stderr);
        exit_atspi_after_failure();
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (wait_for_password_prompt_retirement((unsigned int)viewer_pid, &prompt_scan) != 0) {
        fprintf(stderr,
                "FLUTTER_PEER_X11_FAIL password prompt did not retire "
                "applications=%u nodes=%u password_nodes=%u visible_passwords=%u "
                "ready_passwords=%u characters=%d\n",
                prompt_scan.application_roots, prompt_scan.nodes, prompt_scan.password_nodes,
                prompt_scan.visible_passwords, prompt_scan.ready_passwords,
                prompt_scan.first_password_character_count);
        exit_atspi_after_failure();
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    puts("FLUTTER_PEER_PASSWORD_PROMPT_OK accessible=true characters=22 count_only=true "
         "retired=true typed_via_xtest=true argv_password=false");

    if (wait_for_current_frames(display, &viewer, &history, AUTH_WAIT_MS, 4U,
                                &initial_fresh_ms, &initial_max_age) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL authenticated current pixels unavailable\n", stderr);
        exit_atspi_after_failure();
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_INITIAL_PIXELS_OK first_fresh_ms=%llu maximum_age_ms=%llu distinct=4\n",
           (unsigned long long)initial_fresh_ms, (unsigned long long)initial_max_age);
    if (read_connection_identity(&current_connection) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL exact authenticated TCP identity unavailable\n", stderr);
        exit_atspi_after_failure();
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (read_process_resources(viewer_pid, &baseline_resources) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL initial viewer resources unavailable\n", stderr);
        exit_atspi_after_failure();
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    print_resources("initial", 0U, &baseline_resources);

    if (argc == 6) {
        int keyboard_retirement = strcmp(argv[5], "--keyboard-retirement") == 0;
        int keyboard_input = strcmp(argv[5], "--keyboard-input") == 0;
        int mouse_input = strcmp(argv[5], "--mouse-input") == 0;
        int mouse_retirement = strcmp(argv[5], "--mouse-retirement") == 0;
        int screenshot_unavailable = strcmp(argv[5], "--screenshot-save-unavailable") == 0;
        int clipboard_text = strcmp(argv[5], "--clipboard-text") == 0;
        int clipboard_images = strcmp(argv[5], "--clipboard-images") == 0;
        int partial_loss = strcmp(argv[5], "--network-loss") == 0;
        int network = partial_loss || strcmp(argv[5], "--network-impairment") == 0;
        int suspension_status = screenshot_unavailable ? exercise_screenshot_save_unavailable(
            &viewer, &current_connection, &baseline_resources) : mouse_retirement ? exercise_mouse_retirement(
            source, display, &viewer, argv[4], &current_connection) : mouse_input ? exercise_mouse_input(
            source, display, &viewer, &current_connection, &baseline_resources) :
            keyboard_retirement ? exercise_keyboard_retirement(
            source, display, &viewer, argv[4], &current_connection) : keyboard_input ? exercise_keyboard_input(
            source, display, &viewer, &current_connection, &baseline_resources) :
            (clipboard_text || clipboard_images) ? exercise_clipboard(
            source, display, &viewer, &current_connection, &baseline_resources, clipboard_images) :
            network ? exercise_network_impairment(
            source, display, &viewer, &history, viewer_pid,
            &current_connection, &baseline_resources, partial_loss) : exercise_viewer_suspension(
            source, display, &viewer, &history, viewer_pid, argv[4],
            &current_connection, &baseline_resources);
        if (suspension_status != 0) {
            fputs("FLUTTER_PEER_X11_FAIL selected peer scenario\n", stderr);
            exit_atspi_after_failure();
        } else if (atspi_exit() != 0) {
            fputs("FLUTTER_PEER_X11_FAIL private AT-SPI teardown\n", stderr);
            suspension_status = -1;
        }
        if (!keyboard_retirement && !mouse_retirement &&
            close_viewer(display, viewer.window) != 0) suspension_status = -1;
        XCloseDisplay(display);
        XCloseDisplay(source);
        if (suspension_status != 0) return 1;
        if (screenshot_unavailable) {
            puts("FLUTTER_PEER_SCREENSHOT_SAVE_UNAVAILABLE_OK screenshot_received=true "
                 "save=unavailable error=visible stable_connection=true");
        } else if (mouse_retirement) {
            puts("FLUTTER_PEER_MOUSE_RETIREMENT_OK remote_buttons=3 local_button=preserved "
                 "viewer_exit=abrupt native_releases=true fixture_buttons_released=true");
        } else if (mouse_input) {
            puts("FLUTTER_PEER_MOUSE_INPUT_OK cases=21 button_events=42 drag_moves=2 "
                 "wheel_directions=4 outside_releases=5 reentries=5 side_buttons=2 actual_peer=true native_events=true released=both "
                 "same_window=true stable_connection=true resources=bounded");
        } else if (keyboard_retirement) {
            puts("FLUTTER_PEER_KEYBOARD_RETIREMENT_OK remote_keys=2 local_key=preserved "
                 "viewer_exit=abrupt native_releases=true fixture_keys_released=true");
        } else if (keyboard_input) {
            puts("FLUTTER_PEER_KEYBOARD_INPUT_OK cases=11 events=28 actual_peer=true "
                 "native_key_events=true exact_text=true released=both same_window=true "
                 "stable_connection=true resources=bounded");
        } else if (clipboard_images) {
            puts("FLUTTER_PEER_CLIPBOARD_IMAGES_OK text_cases=8 image_cases=10 directions=both "
                 "kinds=transparent-1x1,rgba-17x13,rgb-63x31,rgba-513x515,rgba-2051x2053 limit_ms=5000 "
                 "actual_peer=true native_readback=true exact_pixels=true same_window=true "
                 "stable_connection=true resources=bounded");
        } else if (clipboard_text) {
            puts("FLUTTER_PEER_CLIPBOARD_TEXT_OK cases=6 directions=both kinds=ascii,unicode,16k "
                 "limit_ms=5000 actual_peer=true native_readback=true same_window=true "
                 "stable_connection=true resources=bounded");
        } else if (partial_loss) {
            puts("FLUTTER_PEER_NETWORK_LOSS_PRESENTATION_OK cycles=3 "
                 "profiles=random3,random8,burst holds_ms=20000,20000,20000 "
                 "recovery_limit_ms=2500 freshness_limit_ms=1000 healthy_ms=3000 "
                 "actual_peer=true x11_pixels=true same_window=true stable_connection=true "
                 "resources=bounded seed=kernel-uncontrolled");
        } else if (network) {
            puts("FLUTTER_PEER_NETWORK_PRESENTATION_OK cycles=9 delay_ms=125 loss_percent=100 "
                 "holds_ms=6000,2000,6000,1750,5750,2250,6250,2500,6500 "
                 "recovery_limit_ms=2500 freshness_limit_ms=1000 "
                 "healthy_ms=3000 actual_peer=true x11_pixels=true same_window=true "
                 "stable_connection=true resources=bounded");
        } else puts("FLUTTER_PEER_SUSPEND_PRESENTATION_OK cycles=3 holds_ms=2000,6000,12000 "
             "recovery_limit_ms=2500 freshness_limit_ms=1000 healthy_ms=3000 "
             "actual_peer=true x11_pixels=true same_window=true stable_connection=true "
             "resources=bounded threads_growth_max=8 fds_growth_max=16 rss_growth_kib_max=131072");
        return 0;
    }

    for (unsigned int cycle = 0U; cycle < FOCUS_CYCLE_COUNT; ++cycle) {
        Window sink = create_focus_sink(display);
        uint64_t background_max_gap;
        uint64_t background_max_age;
        unsigned int background_distinct;
        uint64_t recovery_ms;
        uint64_t recovery_max_age;
        ConnectionIdentity connection_after = {{0}, {0}, 0UL};

        if (sink == 0) {
            fputs("FLUTTER_PEER_X11_FAIL focus sink creation\n", stderr);
            exit_atspi_after_failure();
            close_viewer(display, viewer.window);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
        printf("FLUTTER_PEER_BACKGROUND_OBSERVATION_BEGIN cycle=%u blurred_ms=%u "
               "monotonic_ms=%llu\n",
               cycle + 1U, blur_hold_ms[cycle],
               (unsigned long long)monotonic_millis());
        fflush(stdout);
        if (observe_current_frames_for_duration(
                source, display, &viewer, &history, blur_hold_ms[cycle],
                &background_max_gap, &background_max_age, &background_distinct) != 0) {
            fprintf(stderr,
                    "FLUTTER_PEER_X11_FAIL background freshness exceeded %u ms "
                    "cycle=%u blurred_ms=%u maximum_gap_ms=%llu maximum_age_ms=%llu "
                    "distinct=%u monotonic_ms=%llu\n",
                    FRESH_LIMIT_MS, cycle + 1U, blur_hold_ms[cycle],
                    (unsigned long long)background_max_gap,
                    (unsigned long long)background_max_age, background_distinct,
                    (unsigned long long)monotonic_millis());
            XDestroyWindow(display, sink);
            exit_atspi_after_failure();
            close_viewer(display, viewer.window);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
        printf("FLUTTER_PEER_BACKGROUND_FRESHNESS_OK cycle=%u blurred_ms=%u "
               "maximum_gap_ms=%llu maximum_age_ms=%llu distinct=%u\n",
               cycle + 1U, blur_hold_ms[cycle],
               (unsigned long long)background_max_gap,
               (unsigned long long)background_max_age, background_distinct);
        if (return_focus_with_pointer(display, &viewer) != 0) {
            fputs("FLUTTER_PEER_X11_FAIL real focus/pointer return\n", stderr);
            XDestroyWindow(display, sink);
            exit_atspi_after_failure();
            close_viewer(display, viewer.window);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
        if (wait_for_current_frames(display, &viewer, &history, RECOVERY_LIMIT_MS, 3U,
                                    &recovery_ms, &recovery_max_age) != 0) {
            fprintf(stderr,
                    "FLUTTER_PEER_X11_FAIL focus recovery exceeded %u ms cycle=%u\n",
                    RECOVERY_LIMIT_MS, cycle + 1U);
            XDestroyWindow(display, sink);
            exit_atspi_after_failure();
            close_viewer(display, viewer.window);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
        if (read_connection_identity(&connection_after) != 0 ||
            same_connection(&current_connection, &connection_after) == 0) {
            fputs("FLUTTER_PEER_X11_FAIL focus cycle replaced the authenticated TCP connection\n",
                  stderr);
            XDestroyWindow(display, sink);
            exit_atspi_after_failure();
            close_viewer(display, viewer.window);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
        if (read_process_resources(viewer_pid, &current_resources) != 0 ||
            resources_are_bounded(&baseline_resources, &current_resources) == 0) {
            fputs("FLUTTER_PEER_X11_FAIL viewer resources exceeded focus-cycle bounds\n",
                  stderr);
            XDestroyWindow(display, sink);
            exit_atspi_after_failure();
            close_viewer(display, viewer.window);
            XCloseDisplay(display);
            XCloseDisplay(source);
            return 1;
        }
        print_resources("focus", cycle + 1U, &current_resources);
        printf("FLUTTER_PEER_FOCUS_RECOVERY_OK cycle=%u blurred_ms=%u recovery_ms=%llu "
               "maximum_age_ms=%llu real_pointer=true stable_connection=true\n",
               cycle + 1U, blur_hold_ms[cycle], (unsigned long long)recovery_ms,
               (unsigned long long)recovery_max_age);
        XDestroyWindow(display, sink);
    }

    coord = open_coord_root();
    if (coord < 0) {
        fputs("FLUTTER_PEER_X11_FAIL coordination authority unavailable\n", stderr);
        exit_atspi_after_failure();
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    for (unsigned int sequence = 1U; sequence <= RECONNECT_COUNT; ++sequence) {
        unsigned int generation = sequence + 1U;
        ConnectionIdentity replacement = {{0}, {0}, 0UL};
        ViewerWindow reconnected_viewer = {0};
        uint64_t first_fresh_ms;
        uint64_t maximum_age_ms;

        if (sequence == RECONNECT_COUNT) {
            ConnectionIdentity after = {{0}, {0}, 0UL};
            if (open_trackpad_dialog((unsigned int)viewer_pid, &previous_caption) != 0 ||
                read_connection_identity(&after) != 0 ||
                same_connection(&current_connection, &after) == 0) {
                fputs("FLUTTER_PEER_X11_FAIL stable dialog before reconnect unavailable\n", stderr);
                goto reconnect_failure;
            }
            puts("FLUTTER_PEER_DIALOG_RECONNECT_BEGIN generation=4 stable_dialog=true stable_connection=true");
            fflush(stdout);
        }
        if (request_server_restart(coord, generation) != 0 ||
            wait_for_server_restart(coord, generation) != 0) {
            fprintf(stderr,
                    "FLUTTER_PEER_X11_FAIL server restart transaction generation=%u\n",
                    generation);
            goto reconnect_failure;
        }
        if (wait_for_replacement_connection(&current_connection, &replacement) != 0) {
            fprintf(stderr,
                    "FLUTTER_PEER_X11_FAIL viewer did not reconnect generation=%u\n",
                    generation);
            goto reconnect_failure;
        }
        if (find_viewer_window(display, viewer_pid, &reconnected_viewer) != 0 ||
            reconnected_viewer.window != viewer.window) {
            fputs("FLUTTER_PEER_X11_FAIL reconnect replaced the exact viewer window\n", stderr);
            goto reconnect_failure;
        }
        viewer = reconnected_viewer;
        if (wait_for_current_frames(display, &viewer, &history,
                                    AUTH_WAIT_MS, 4U, &first_fresh_ms,
                                    &maximum_age_ms) != 0) {
            fprintf(stderr,
                    "FLUTTER_PEER_X11_FAIL current pixels unavailable after reconnect "
                    "generation=%u\n",
                    generation);
            goto reconnect_failure;
        }
        if (sequence == RECONNECT_COUNT) {
            ConnectionIdentity after = {{0}, {0}, 0UL};
            if (wait_for_dialog_retirement((unsigned int)viewer_pid) != 0 ||
                read_connection_identity(&after) != 0 || same_connection(&replacement, &after) == 0) {
                fputs("FLUTTER_PEER_X11_FAIL old dialog retirement after reconnect unproved\n", stderr);
                goto reconnect_failure;
            }
            puts("FLUTTER_PEER_DIALOG_RECONNECT_RETIRED generation=4 fresh_pixels=true same_window=true");
            fflush(stdout);
        }
        if (read_process_resources(viewer_pid, &current_resources) != 0 ||
            resources_are_bounded(&baseline_resources, &current_resources) == 0) {
            fputs("FLUTTER_PEER_X11_FAIL viewer resources exceeded reconnect bounds\n", stderr);
            goto reconnect_failure;
        }
        print_resources("reconnect", sequence, &current_resources);
        printf("FLUTTER_PEER_RECONNECT_OK sequence=%u generation=%u old_inode=%lu "
               "new_inode=%lu first_fresh_ms=%llu maximum_age_ms=%llu "
               "same_window=true cached_credential=true\n",
               sequence, generation, current_connection.inode, replacement.inode,
               (unsigned long long)first_fresh_ms,
               (unsigned long long)maximum_age_ms);
        current_connection = replacement;
    }
    if (close(coord) != 0) {
        coord = -1;
        fputs("FLUTTER_PEER_X11_FAIL coordination authority close\n", stderr);
        goto reconnect_failure;
    }
    coord = -1;
    /* Measure connection/display behavior before potentially blocking geometry queries. */
    if (exercise_dialog_resize(display, &viewer, &current_connection, previous_caption) != 0)
        goto reconnect_failure;
    puts("FLUTTER_PEER_DIALOG_RECONNECT_OK generation=4 retired=true recreated=true "
         "distinct_accessible=true same_window=true fresh_pixels=true");
    g_clear_object(&previous_caption);
    if (atspi_exit() != 0) {
        fputs("FLUTTER_PEER_X11_FAIL private AT-SPI teardown\n", stderr);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (wait_for_current_frames(display, &viewer, &history, RECOVERY_LIMIT_MS, 3U,
                                &initial_fresh_ms, &initial_max_age) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL current pixels unavailable after explicit dialog close\n",
              stderr);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    if (read_process_resources(viewer_pid, &current_resources) != 0 ||
        resources_are_bounded(&baseline_resources, &current_resources) == 0) {
        fputs("FLUTTER_PEER_X11_FAIL viewer resources exceeded dialog-retirement bounds\n", stderr);
        close_viewer(display, viewer.window);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    printf("FLUTTER_PEER_DIALOG_RESOURCES_OK rss_kib=%llu threads=%u fds=%u\n",
           current_resources.rss_kib, current_resources.threads, current_resources.descriptors);
    puts("FLUTTER_PEER_RESOURCE_BOUNDS_OK reconnects=3 focus_cycles=3 "
         "threads_growth_max=8 fds_growth_max=16 rss_growth_kib_max=131072");
    if (close_viewer(display, viewer.window) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL WM_DELETE_WINDOW\n", stderr);
        XCloseDisplay(display);
        XCloseDisplay(source);
        return 1;
    }
    puts("FLUTTER_PEER_PRESENTATION_OK actual_peer=true password_prompt=true capture=true "
         "transport=true decode=true flutter_texture=true x11_pixels=true focus_recovery=true "
         "background_freshness=true reconnects=3 resources=bounded");
    XCloseDisplay(display);
    XCloseDisplay(source);
    return 0;
reconnect_failure:
    if (coord >= 0 && close(coord) != 0) {
        fputs("FLUTTER_PEER_X11_FAIL coordination authority close after primary failure\n", stderr);
    }
    g_clear_object(&previous_caption);
    exit_atspi_after_failure();
    close_viewer(display, viewer.window);
    XCloseDisplay(display);
    XCloseDisplay(source);
    return 1;
}
