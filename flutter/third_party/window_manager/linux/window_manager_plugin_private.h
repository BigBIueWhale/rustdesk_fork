#ifndef FLUTTER_PLUGIN_WINDOW_MANAGER_PLUGIN_PRIVATE_H_
#define FLUTTER_PLUGIN_WINDOW_MANAGER_PLUGIN_PRIVATE_H_

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

// Internal registration boundary used by the native lifecycle regression.
// Production registration derives this exact window from the registrar view.
GObject* window_manager_plugin_register_with_registrar_for_window(
    FlPluginRegistrar* registrar,
    GtkWindow* window);

#endif  // FLUTTER_PLUGIN_WINDOW_MANAGER_PLUGIN_PRIVATE_H_
