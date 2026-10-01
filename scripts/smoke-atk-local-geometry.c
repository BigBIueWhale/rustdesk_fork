#define _GNU_SOURCE
#include <atk/atk.h>
#include <dlfcn.h>
#include <gtk/gtk.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Temporary same-artifact counterfactual, not a supported product mode. */
enum { MAX_VIEWS = 4, MAX_ID_BYTES = 512 };
typedef struct {
    GWeakRef widget, accessible, socket;
    int plug;
} Owner;
typedef struct {
    GWeakRef plug;
    gchar *id;
    int owner;
} Plug;
static Owner owners[MAX_VIEWS];
static Plug plugs[MAX_VIEWS];
static unsigned owner_count, plug_count, receipts;
static gboolean initialized;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static AtkObject *(*real_widget_accessible)(GtkWidget *);
static gchar *(*real_plug_id)(AtkPlug *);
static void (*real_socket_embed)(AtkSocket *, const gchar *);
static void (*real_extents)(AtkComponent *, gint *, gint *, gint *, gint *, AtkCoordType);

static void refuse(const char *reason) {
    fprintf(stderr, "ATK_LOCAL_GEOMETRY_REFUSED reason=%s\n", reason);
    fflush(stderr);
    _exit(125);
}

static void initialize(void) {
    real_widget_accessible = dlsym(RTLD_NEXT, "gtk_widget_get_accessible");
    real_plug_id = dlsym(RTLD_NEXT, "atk_plug_get_id");
    real_socket_embed = dlsym(RTLD_NEXT, "atk_socket_embed");
    real_extents = dlsym(RTLD_NEXT, "atk_component_get_extents");
    if (!real_widget_accessible || !real_plug_id || !real_socket_embed || !real_extents)
        refuse("missing-native-api");
    for (unsigned i = 0; i < MAX_VIEWS; i++) {
        g_weak_ref_init(&owners[i].widget, NULL);
        g_weak_ref_init(&owners[i].accessible, NULL);
        g_weak_ref_init(&owners[i].socket, NULL);
        g_weak_ref_init(&plugs[i].plug, NULL);
        owners[i].plug = -1;
        plugs[i].owner = -1;
    }
    initialized = TRUE;
}

__attribute__((destructor)) static void retire(void) {
    if (!initialized) return;
    for (unsigned i = 0; i < MAX_VIEWS; i++) {
        g_weak_ref_clear(&owners[i].widget);
        g_weak_ref_clear(&owners[i].accessible);
        g_weak_ref_clear(&owners[i].socket);
        g_weak_ref_clear(&plugs[i].plug);
        g_free(plugs[i].id);
    }
}

static void ready(void) {
    if (pthread_once(&once, initialize) != 0) refuse("initialization");
}

static void require_main_thread(void) {
    if (syscall(SYS_gettid) != getpid()) refuse("non-main-thread");
}

static gboolean exact_type(gpointer object, const char *name) {
    return object && strcmp(G_OBJECT_TYPE_NAME(object), name) == 0;
}

static gboolean same(GWeakRef *weak, gpointer expected) {
    GObject *object = g_weak_ref_get(weak);
    gboolean equal = object && object == expected;
    if (object) g_object_unref(object);
    return equal;
}

AtkObject *gtk_widget_get_accessible(GtkWidget *widget) {
    ready();
    AtkObject *accessible = real_widget_accessible(widget);
    if (!exact_type(widget, "FlView")) return accessible;
    require_main_thread();
    if (!exact_type(accessible, "FlSocketAccessible") || !GTK_IS_ACCESSIBLE(accessible)
        || gtk_accessible_get_widget(GTK_ACCESSIBLE(accessible)) != widget
        || atk_object_get_n_accessible_children(accessible) != 1)
        refuse("widget-accessible-association");
    AtkObject *socket = atk_object_ref_accessible_child(accessible, 0);
    if (!ATK_IS_SOCKET(socket)) refuse("native-socket-child");
    for (unsigned i = 0; i < owner_count; i++) {
        if (!same(&owners[i].widget, widget)) continue;
        if (!same(&owners[i].accessible, accessible) || !same(&owners[i].socket, socket))
            refuse("changed-widget-association");
        g_object_unref(socket);
        return accessible;
    }
    if (owner_count == MAX_VIEWS) refuse("view-bound");
    Owner *owner = &owners[owner_count++];
    g_weak_ref_set(&owner->widget, widget);
    g_weak_ref_set(&owner->accessible, accessible);
    g_weak_ref_set(&owner->socket, socket);
    g_object_unref(socket);
    return accessible;
}

gchar *atk_plug_get_id(AtkPlug *plug) {
    ready();
    gchar *id = real_plug_id(plug);
    if (!exact_type(plug, "FlViewAccessible")) return id;
    require_main_thread();
    if (!id || strnlen(id, MAX_ID_BYTES + 1) > MAX_ID_BYTES || !*id)
        refuse("plug-id-bound");
    for (unsigned i = 0; i < plug_count; i++) {
        if (!same(&plugs[i].plug, plug)) continue;
        if (strcmp(plugs[i].id, id) != 0) refuse("changed-plug-id");
        return id;
    }
    if (plug_count == MAX_VIEWS) refuse("plug-bound");
    Plug *entry = &plugs[plug_count++];
    g_weak_ref_set(&entry->plug, plug);
    entry->id = g_strdup(id);
    return id;
}

void atk_socket_embed(AtkSocket *socket, const gchar *id) {
    ready();
    require_main_thread();
    int owner_index = -1, plug_index = -1;
    for (unsigned i = 0; i < owner_count; i++) {
        if (!same(&owners[i].socket, socket)) continue;
        if (owner_index != -1) refuse("ambiguous-socket");
        owner_index = (int)i;
    }
    if (id && strnlen(id, MAX_ID_BYTES + 1) <= MAX_ID_BYTES) {
        for (unsigned i = 0; i < plug_count; i++) {
            if (strcmp(plugs[i].id, id) != 0) continue;
            if (plug_index != -1) refuse("ambiguous-plug-id");
            plug_index = (int)i;
        }
    }
    if (owner_index == -1 && plug_index == -1) {
        real_socket_embed(socket, id);
        return;
    }
    if (owner_index == -1 || plug_index == -1) refuse("incomplete-embed-association");
    GObject *owner = g_weak_ref_get(&owners[owner_index].accessible);
    GObject *plug = g_weak_ref_get(&plugs[plug_index].plug);
    if (!owner || !plug) refuse("retired-embed-owner");
    if (plugs[plug_index].owner != -1 && plugs[plug_index].owner != owner_index)
        refuse("replaced-embed-owner");
    if (owners[owner_index].plug != -1 && owners[owner_index].plug != plug_index)
        refuse("replaced-socket-plug");
    AtkObject *parent = atk_object_get_parent(ATK_OBJECT(socket));
    if (parent && parent != ATK_OBJECT(owner)) refuse("foreign-socket-parent");
    if (!parent) atk_object_set_parent(ATK_OBJECT(socket), ATK_OBJECT(owner));
    if (atk_object_get_parent(ATK_OBJECT(socket)) != ATK_OBJECT(owner))
        refuse("parent-binding");
    plugs[plug_index].owner = owner_index;
    owners[owner_index].plug = plug_index;
    real_socket_embed(socket, id);
    fprintf(stderr, "ATK_LOCAL_GEOMETRY_BOUND view=%d parent_before=%s parent_after=exact native_embed=unchanged\n",
            owner_index, parent ? "exact" : "absent");
    fflush(stderr);
    g_object_unref(plug);
    g_object_unref(owner);
}

void atk_component_get_extents(AtkComponent *component, gint *x, gint *y,
                               gint *width, gint *height, AtkCoordType coords) {
    ready();
    if (!exact_type(component, "FlViewAccessible")) {
        real_extents(component, x, y, width, height, coords);
        return;
    }
    require_main_thread();
    int plug_index = -1;
    for (unsigned i = 0; i < plug_count; i++) {
        if (!same(&plugs[i].plug, component)) continue;
        if (plug_index != -1) refuse("ambiguous-geometry-plug");
        plug_index = (int)i;
    }
    if (plug_index == -1) refuse("unknown-geometry-plug");
    int index = plugs[plug_index].owner;
    if (index < 0 || (unsigned)index >= owner_count) refuse("unbound-geometry-plug");
    if (owners[index].plug != plug_index) refuse("replaced-geometry-plug");
    GObject *widget = g_weak_ref_get(&owners[index].widget);
    GObject *owner = g_weak_ref_get(&owners[index].accessible);
    GObject *socket = g_weak_ref_get(&owners[index].socket);
    if (!widget || !owner || !socket || !exact_type(widget, "FlView")
        || !exact_type(owner, "FlSocketAccessible") || !ATK_IS_SOCKET(socket)
        || !ATK_IS_COMPONENT(socket) || !GTK_IS_ACCESSIBLE(owner)
        || gtk_accessible_get_widget(GTK_ACCESSIBLE(owner)) != GTK_WIDGET(widget)
        || real_widget_accessible(GTK_WIDGET(widget)) != ATK_OBJECT(owner)
        || atk_object_get_n_accessible_children(ATK_OBJECT(owner)) != 1
        || atk_object_get_parent(ATK_OBJECT(socket)) != ATK_OBJECT(owner)
        || !atk_socket_is_occupied(ATK_SOCKET(socket)))
        refuse("stale-geometry-association");
    AtkObject *child = atk_object_ref_accessible_child(ATK_OBJECT(owner), 0);
    if (child != ATK_OBJECT(socket)) refuse("changed-socket-child");
    g_object_unref(child);
    if (coords != ATK_XY_SCREEN && coords != ATK_XY_WINDOW)
        refuse("unsupported-diagnostic-coordinates");
    gint gx = -1, gy = -1, gw = -1, gh = -1;
    real_extents(ATK_COMPONENT(socket), &gx, &gy, &gw, &gh, coords);
    if (x) *x = gx;
    if (y) *y = gy;
    if (width) *width = gw;
    if (height) *height = gh;
    if (receipts < 16) {
        receipts++;
        fprintf(stderr, "ATK_LOCAL_GEOMETRY_NATIVE view=%d coords=%d x=%d y=%d width=%d height=%d source=exact-gtk-owner cached=false\n",
                index, (int)coords, gx, gy, gw, gh);
        fflush(stderr);
    }
    g_object_unref(socket);
    g_object_unref(owner);
    g_object_unref(widget);
}
