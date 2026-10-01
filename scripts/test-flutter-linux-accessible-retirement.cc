// Executes the real node, root and text-field implementations with a recording
// engine boundary. This is an ATK/GObject unit test, not a running Flutter engine,
// FlView teardown test, privileged receiver test, or app replay. The candidate
// first exercises real GTK widget/accessibility lifetime on its owned X server.
#include "flutter/shell/platform/linux/fl_accessible_node.h"
#include "flutter/shell/platform/linux/fl_accessible_text_field.h"
#include "flutter/shell/platform/linux/fl_view_accessible.h"
#include "flutter/shell/platform/linux/public/flutter_linux/fl_standard_message_codec.h"
#include "flutter/shell/platform/linux/public/flutter_linux/fl_value.h"

#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <gtk/gtk-a11y.h>

struct _FlEngine {
  GObject parent_instance;
  guint dispatches;
  gchar* last_text;
  gint selection_base;
  gint selection_extent;
  FlAccessibleNode* retire_on_dispatch;
  gboolean dispose_on_dispatch;
};

G_DEFINE_TYPE(FlEngine, fl_engine, G_TYPE_OBJECT)

static void fl_engine_finalize(GObject* object) {
  g_free(FL_ENGINE(object)->last_text);
  G_OBJECT_CLASS(fl_engine_parent_class)->finalize(object);
}

static void fl_engine_class_init(FlEngineClass* klass) {
  G_OBJECT_CLASS(klass)->finalize = fl_engine_finalize;
}

static void fl_engine_init(FlEngine* self) {
  self->selection_base = -1;
  self->selection_extent = -1;
}

#if !defined(LEGACY_BASELINE)
struct TestSemanticsView { GtkBox parent_instance; };
struct TestSemanticsViewClass { GtkBoxClass parent_class; };
G_DEFINE_TYPE(TestSemanticsView, test_semantics_view, GTK_TYPE_BOX)

static void test_semantics_view_class_init(TestSemanticsViewClass* klass) {
  gtk_widget_class_set_accessible_type(GTK_WIDGET_CLASS(klass),
                                       fl_view_accessible_get_type());
}

static void test_semantics_view_init(TestSemanticsView* self) {
  // Match early GTK accessibility access before FlView's engine fields exist.
  gtk_widget_get_accessible(GTK_WIDGET(self));
  gtk_widget_set_can_focus(GTK_WIDGET(self), TRUE);
  gtk_container_add(GTK_CONTAINER(self), gtk_event_box_new());
}

static GtkWidget* new_generation_widget() {
  return GTK_WIDGET(g_object_ref_sink(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0)));
}

static GtkWidget* new_bound_view(FlEngine* engine) {
  GtkWidget* widget = GTK_WIDGET(g_object_ref_sink(
      g_object_new(test_semantics_view_get_type(), nullptr)));
  FlViewAccessible* accessible = FL_VIEW_ACCESSIBLE(gtk_widget_get_accessible(widget));
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
  gint x = 99, y = 98, width = 97, height = 96;
  atk_component_get_extents(ATK_COMPONENT(accessible), &x, &y, &width, &height, ATK_XY_WINDOW);
  g_assert_cmpint(x, ==, -1);
  g_assert_cmpint(y, ==, -1);
  g_assert_cmpint(width, ==, -1);
  g_assert_cmpint(height, ==, -1);
  g_assert_true(fl_view_accessible_bind_engine(accessible, engine, 7));
  g_assert_false(fl_view_accessible_bind_engine(accessible, engine, 7));
  return widget;
}

static FlutterTransformation identity_transform() {
  FlutterTransformation transform = {};
  transform.scaleX = transform.scaleY = transform.pers2 = 1;
  return transform;
}

static void test_gtk_widget_lifetime() {
  g_assert_true(gtk_init_check(nullptr, nullptr));
  GtkWidget* window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  g_object_ref_sink(window);
  GtkWidget* box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
  gtk_container_add(GTK_CONTAINER(window), box);
  gtk_widget_show_all(window);
  gdk_display_sync(gtk_widget_get_display(window));
  g_assert_true(gtk_widget_get_realized(box));
  g_assert_true(gtk_widget_get_mapped(box));
  g_assert_nonnull(gtk_widget_get_window(box));
  g_autoptr(AtkObject) accessible = ATK_OBJECT(g_object_ref(gtk_widget_get_accessible(box)));
  g_assert_true(GTK_IS_ACCESSIBLE(accessible));
  g_assert_true(gtk_accessible_get_widget(GTK_ACCESSIBLE(accessible)) == box);
  gtk_widget_destroy(window);
  g_assert_null(gtk_accessible_get_widget(GTK_ACCESSIBLE(accessible)));
  g_object_unref(window);
  std::puts("ENGINE_GTK_WIDGET_LIFETIME=pass backend=x11 mapped=true retained_accessible=unbound destroyed=true");
  std::fflush(stdout);
}

static void retire_on_child_removal(AtkObject* object, guint, gpointer, gpointer) {
  fl_accessible_node_retire(FL_ACCESSIBLE_NODE(object));
}

static void update_tree(FlViewAccessible* accessible, const char* label,
                        gboolean siblings = FALSE) {
  FlutterSemanticsFlags flags = {};
  int32_t children[] = {9, 11};
  FlutterSemanticsNode2 root = {};
  root.id = 0;
  root.label = label;
  root.value = "";
  root.flags2 = &flags;
  root.transform = identity_transform();
  root.child_count = siblings ? 2 : 1;
  root.children_in_traversal_order = children;
  FlutterSemanticsNode2 child = {};
  child.id = 9;
  child.label = "child";
  child.value = "";
  child.flags2 = &flags;
  child.transform = identity_transform();
  child.actions = kFlutterSemanticsActionTap;
  FlutterSemanticsNode2 sibling = child;
  sibling.id = 11;
  FlutterSemanticsNode2* nodes[] = {&root, &child, &sibling};
  FlutterSemanticsUpdate2 update = {};
  update.node_count = siblings ? 3 : 2;
  update.nodes = nodes;
  fl_view_accessible_handle_update_semantics(accessible, &update);
}

static void reset_on_root_add(AtkObject* accessible, guint, gpointer, gpointer) {
  fl_view_accessible_reset(FL_VIEW_ACCESSIBLE(accessible));
}

struct TreeRevocation {
  FlEngine* engine;
  FlAccessibleNode* first;
  FlAccessibleNode* second;
  guint notifications;
  FlViewAccessible* accessible;
  guint operation;
};

static void probe_tree_revocation(AtkObject*, const gchar*, gboolean state,
                                   TreeRevocation* context) {
  g_assert_true(state);
  context->notifications++;
  const guint dispatches = context->engine->dispatches;
  const gboolean first = atk_action_do_action(ATK_ACTION(context->first), 0);
  const gboolean second = atk_action_do_action(ATK_ACTION(context->second), 0);
  fl_accessible_node_perform_action(context->first, kFlutterSemanticsActionTap, nullptr);
  fl_accessible_node_perform_action(context->second, kFlutterSemanticsActionTap, nullptr);
  if (first || second || context->engine->dispatches != dispatches) {
    std::printf("ENGINE_ACCESSIBLE_TREE_REVOCATION_FAILURE notification=%u first=%d second=%d dispatches=%u\n",
                context->notifications, first, second,
                context->engine->dispatches - dispatches);
    std::fflush(stdout);
  }
  g_assert_false(first);
  g_assert_false(second);
  g_assert_cmpuint(context->engine->dispatches, ==, dispatches);
  FlAccessibleNode* nodes[] = {context->first, context->second};
  for (FlAccessibleNode* node : nodes) {
    g_autoptr(AtkStateSet) state = atk_object_ref_state_set(ATK_OBJECT(node));
    g_assert_true(atk_state_set_contains_state(state, ATK_STATE_DEFUNCT));
    g_assert_null(atk_object_get_name(ATK_OBJECT(node)));
    g_assert_cmpint(atk_text_get_character_count(ATK_TEXT(node)), ==, 0);
    g_assert_cmpint(atk_action_get_n_actions(ATK_ACTION(node)), ==, 0);
  }
  if (context->notifications == 1 && context->operation == 3) {
    fl_view_accessible_retire(context->accessible);
  } else if (context->notifications == 1 && context->operation == 4) {
    g_object_run_dispose(G_OBJECT(context->accessible));
  }
}

static void test_tree_revocation(FlEngine* engine) {
  for (guint operation = 0; operation < 5; operation++) {
    g_autoptr(GtkWidget) widget = new_bound_view(engine);
    g_autoptr(FlViewAccessible) accessible = FL_VIEW_ACCESSIBLE(
        g_object_ref(gtk_widget_get_accessible(widget)));
    update_tree(accessible, "whole tree", TRUE);
    g_autoptr(AtkObject) root = atk_object_ref_accessible_child(ATK_OBJECT(accessible), 0);
    g_assert_nonnull(root);
    g_autoptr(AtkObject) first = atk_object_ref_accessible_child(root, 0);
    g_autoptr(AtkObject) second = atk_object_ref_accessible_child(root, 1);
    g_assert_nonnull(first);
    g_assert_nonnull(second);
    g_assert_true(atk_action_do_action(ATK_ACTION(first), 0));
    g_assert_true(atk_action_do_action(ATK_ACTION(second), 0));
    TreeRevocation context = {engine, FL_ACCESSIBLE_NODE(first), FL_ACCESSIBLE_NODE(second),
                              0, accessible, operation};
    g_signal_connect(first, "state-change::defunct", G_CALLBACK(probe_tree_revocation), &context);
    g_signal_connect(second, "state-change::defunct", G_CALLBACK(probe_tree_revocation), &context);
    const guint dispatches = engine->dispatches;
    switch (operation) {
      case 0:
      case 3:
      case 4:
        fl_view_accessible_reset(accessible);
        break;
      case 1:
        fl_view_accessible_retire(accessible);
        break;
      case 2:
        g_object_run_dispose(G_OBJECT(accessible));
        break;
    }
    g_assert_cmpuint(context.notifications, ==, 2);
    g_assert_cmpuint(engine->dispatches, ==, dispatches);
    g_signal_handlers_disconnect_by_data(first, &context);
    g_signal_handlers_disconnect_by_data(second, &context);
    if (operation >= 3) {
      update_tree(accessible, "retired during reset", TRUE);
      g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
    }
  }
  std::puts("ENGINE_ACCESSIBLE_TREE_REVOCATION=pass unit=real-root first_notification=closed indexed_direct=refused reset_retire_dispose=closed reentrant_owner=closed");
  std::fflush(stdout);
}

static void test_root(FlEngine* engine) {
  const guint dispatches = engine->dispatches;
  g_autoptr(GtkWidget) widget = new_bound_view(engine);
  g_autoptr(FlViewAccessible) accessible = FL_VIEW_ACCESSIBLE(
      g_object_ref(gtk_widget_get_accessible(widget)));
  update_tree(accessible, "original root");
  g_autoptr(AtkObject) old_root = atk_object_ref_accessible_child(ATK_OBJECT(accessible), 0);
  g_assert_nonnull(old_root);
  g_autoptr(AtkObject) old_child = atk_object_ref_accessible_child(old_root, 0);
  g_assert_nonnull(old_child);
  g_assert_true(atk_action_do_action(ATK_ACTION(old_child), 0));
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 1);
  fl_view_accessible_reset(accessible);
  fl_view_accessible_reset(accessible);
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
  g_assert_cmpint(atk_object_get_n_accessible_children(old_root), ==, 0);
  g_assert_null(atk_object_get_parent(old_child));
  g_assert_false(atk_action_do_action(ATK_ACTION(old_child), 0));
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 1);
  update_tree(accessible, "replacement root");
  g_autoptr(AtkObject) fresh_root = atk_object_ref_accessible_child(ATK_OBJECT(accessible), 0);
  g_assert_nonnull(fresh_root);
  g_assert_true(fresh_root != old_root);
  g_autoptr(AtkObject) fresh_child = atk_object_ref_accessible_child(fresh_root, 0);
  g_assert_nonnull(fresh_child);
  g_assert_true(fresh_child != old_child);
  g_assert_true(atk_action_do_action(ATK_ACTION(fresh_child), 0));
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 2);
  fl_view_accessible_reset(accessible);
  const gulong handler = g_signal_connect(accessible, "children-changed::add",
                                         G_CALLBACK(reset_on_root_add), nullptr);
  g_assert_cmpuint(handler, !=, 0);
  update_tree(accessible, "interrupted root");
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
  g_signal_handler_disconnect(accessible, handler);
  update_tree(accessible, "healthy root");
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 1);
  fl_view_accessible_retire(accessible);
  fl_view_accessible_retire(accessible);
  update_tree(accessible, "late root");
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
  g_assert_false(atk_action_do_action(ATK_ACTION(fresh_child), 0));
  g_object_run_dispose(G_OBJECT(accessible));
  fl_view_accessible_reset(accessible);
  update_tree(accessible, "disposed root");
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
  g_autoptr(AtkStateSet) state = atk_object_ref_state_set(ATK_OBJECT(accessible));
  g_assert_nonnull(state);
  g_assert_true(atk_state_set_contains_state(state, ATK_STATE_DEFUNCT));
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 2);
  g_assert_false(atk_component_grab_focus(ATK_COMPONENT(accessible)));
  g_assert_false(atk_component_set_position(ATK_COMPONENT(accessible), 1, 2, ATK_XY_SCREEN));
  g_assert_false(atk_component_set_size(ATK_COMPONENT(accessible), 3, 4));
  g_assert_false(atk_component_set_extents(ATK_COMPONENT(accessible), 1, 2, 3, 4, ATK_XY_SCREEN));
  std::puts("ENGINE_ACCESSIBLE_ROOT_RETIREMENT=pass unit=real-root boundary=recording-engine reset=true replacement=true reentrant=true disposed=true");
  std::fflush(stdout);
}

static void assert_text_field_closed(FlAccessibleNode* text, FlEngine* engine) {
  const guint dispatches = engine->dispatches;
  g_assert_cmpint(atk_text_get_character_count(ATK_TEXT(text)), ==, 0);
  g_autofree gchar* value = atk_text_get_text(ATK_TEXT(text), 0, -1);
  g_assert_cmpstr(value, ==, "");
  g_assert_cmpuint(atk_text_get_character_at_offset(ATK_TEXT(text), 0), ==, 0);
  g_assert_cmpint(atk_text_get_caret_offset(ATK_TEXT(text)), ==, -1);
  g_assert_cmpint(atk_text_get_n_selections(ATK_TEXT(text)), ==, 0);
  const AtkTextGranularity granularities[] = {
      ATK_TEXT_GRANULARITY_CHAR, ATK_TEXT_GRANULARITY_WORD,
      ATK_TEXT_GRANULARITY_SENTENCE, ATK_TEXT_GRANULARITY_LINE,
      ATK_TEXT_GRANULARITY_PARAGRAPH};
  for (const auto granularity : granularities) {
    gint start = 99, end = 98;
    g_autofree gchar* part = atk_text_get_string_at_offset(
        ATK_TEXT(text), 0, granularity, &start, &end);
    g_assert_null(part);
    g_assert_cmpint(start, ==, -1);
    g_assert_cmpint(end, ==, -1);
  }
  gint start = 99, end = 98;
  g_autofree gchar* selection = atk_text_get_selection(ATK_TEXT(text), 0, &start, &end);
  g_assert_null(selection);
  g_assert_cmpint(start, ==, -1);
  g_assert_cmpint(end, ==, -1);
  g_assert_false(atk_text_set_caret_offset(ATK_TEXT(text), 0));
  g_assert_false(atk_text_add_selection(ATK_TEXT(text), 0, 1));
  g_assert_false(atk_text_remove_selection(ATK_TEXT(text), 0));
  g_assert_false(atk_text_set_selection(ATK_TEXT(text), 0, 0, 1));
  gint position = 0;
  atk_editable_text_insert_text(ATK_EDITABLE_TEXT(text), "late", 4, &position);
  atk_editable_text_delete_text(ATK_EDITABLE_TEXT(text), 0, 1);
  atk_editable_text_set_text_contents(ATK_EDITABLE_TEXT(text), "late");
  atk_editable_text_copy_text(ATK_EDITABLE_TEXT(text), 0, 1);
  atk_editable_text_cut_text(ATK_EDITABLE_TEXT(text), 0, 1);
  atk_editable_text_paste_text(ATK_EDITABLE_TEXT(text), 0);
  fl_accessible_node_set_value(text, "late semantics");
  fl_accessible_node_set_text_selection(text, 0, 2);
  g_assert_cmpint(position, ==, 0);
  g_assert_cmpuint(engine->dispatches, ==, dispatches);
  g_assert_cmpint(atk_text_get_character_count(ATK_TEXT(text)), ==, 0);
  g_assert_cmpint(atk_text_get_caret_offset(ATK_TEXT(text)), ==, -1);
}

struct TextRetirement {
  FlEngine* engine;
  gboolean dispose;
  guint notifications;
};

static void test_generation(FlEngine* engine) {
  g_autoptr(FlSemanticsGeneration) raw = FL_SEMANTICS_GENERATION(
      g_object_new(fl_semantics_generation_get_type(), nullptr));
  g_assert_false(fl_semantics_generation_is_active(raw));
  g_assert_null(fl_accessible_node_new(raw, 9));
  g_autoptr(FlAccessibleNode) ownerless = FL_ACCESSIBLE_NODE(
      g_object_new(fl_accessible_node_get_type(), nullptr));
  g_assert_false(fl_accessible_node_is_live(ownerless));
  g_assert_false(fl_accessible_node_perform_action(ownerless, kFlutterSemanticsActionTap, nullptr));
  g_assert_null(g_object_class_find_property(G_OBJECT_GET_CLASS(ownerless), "engine"));
  g_assert_null(g_object_class_find_property(G_OBJECT_GET_CLASS(ownerless), "view-id"));
  for (guint operation = 0; operation < 5; operation++) {
    g_autoptr(GtkWidget) widget = new_generation_widget();
    g_autoptr(FlSemanticsGeneration) generation = fl_semantics_generation_new(
        GTK_ACCESSIBLE(gtk_widget_get_accessible(widget)), engine, 7);
    g_autoptr(FlAccessibleNode) node = fl_accessible_node_new(generation, 9);
    g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(generation, 10);
    fl_accessible_node_set_actions(node, kFlutterSemanticsActionTap);
    fl_accessible_node_set_value(text, "original");
    fl_accessible_node_set_text_selection(text, 1, 3);
    g_assert_true(atk_action_do_action(ATK_ACTION(node), 0));
    g_assert_cmpint(atk_text_get_character_count(ATK_TEXT(text)), ==, 8);
    const guint dispatches = engine->dispatches;
    if (operation == 0) {
      fl_semantics_generation_retire(generation);
      fl_semantics_generation_retire(generation);
    } else if (operation == 1) {
      g_clear_object(&generation);
    } else if (operation == 2) {
      g_object_run_dispose(G_OBJECT(generation));
      g_object_run_dispose(G_OBJECT(generation));
    } else if (operation == 3) {
      gtk_widget_destroy(widget);
    } else {
      g_clear_object(&widget);
    }
    g_assert_false(fl_accessible_node_is_live(node));
    g_assert_false(atk_action_do_action(ATK_ACTION(node), 0));
    g_assert_false(fl_accessible_node_perform_action(node, kFlutterSemanticsActionTap, nullptr));
    if (generation != nullptr) {
      g_assert_false(fl_semantics_generation_is_active(generation));
      g_assert_null(fl_accessible_node_new(generation, 9));
    }
    assert_text_field_closed(text, engine);
    g_assert_cmpuint(engine->dispatches, ==, dispatches);
  }
  std::puts("ENGINE_SEMANTICS_GENERATION=pass default=closed owner_loss=closed retired_disposed=closed retained_text=closed old_properties=absent");
  std::fflush(stdout);
}

struct GeometryTree {
  FlutterSemanticsFlags flags = {};
  int32_t root_children[1] = {9};
  int32_t parent_children[1] = {11};
  FlutterSemanticsNode2 root = {}, parent = {}, child = {};

  explicit GeometryTree(gint scale) {
    root.id = 0;
    parent.id = 9;
    child.id = 11;
    root.label = parent.label = child.label = "";
    root.value = parent.value = child.value = "";
    root.flags2 = parent.flags2 = child.flags2 = &flags;
    root.rect = {0, 0, 120, 90};
    parent.rect = {0, 0, 100, 80};
    child.rect = {0, 0, 20, 10};
    root.transform = parent.transform = child.transform = identity_transform();
    // RenderView contributes logical-to-physical scale to the root semantics.
    root.transform.scaleX = root.transform.scaleY = scale;
    parent.transform.transX = 40;
    parent.transform.transY = 50;
    child.transform.transX = 5;
    child.transform.transY = 7;
    parent.actions = child.actions = kFlutterSemanticsActionTap;
    root.child_count = parent.child_count = 1;
    root.children_in_traversal_order = root_children;
    parent.children_in_traversal_order = parent_children;
  }

  void publish(FlViewAccessible* accessible) {
    FlutterSemanticsNode2* nodes[] = {&root, &parent, &child};
    FlutterSemanticsUpdate2 update = {};
    update.node_count = 3;
    update.nodes = nodes;
    fl_view_accessible_handle_update_semantics(accessible, &update);
  }
};

static void assert_extents(AtkObject* object, AtkCoordType coordinates,
                           gint x, gint y, gint width, gint height) {
  gint bounds[4] = {99, 98, 97, 96}, position[2] = {99, 98}, size[2] = {99, 98};
  atk_component_get_extents(ATK_COMPONENT(object), &bounds[0], &bounds[1],
                            &bounds[2], &bounds[3], coordinates);
  atk_component_get_position(ATK_COMPONENT(object), &position[0], &position[1], coordinates);
  atk_component_get_size(ATK_COMPONENT(object), &size[0], &size[1]);
  const gint expected[4] = {x, y, width, height};
  for (guint i = 0; i < 4; i++) g_assert_cmpint(bounds[i], ==, expected[i]);
  g_assert_cmpint(position[0], ==, x);
  g_assert_cmpint(position[1], ==, y);
  g_assert_cmpint(size[0], ==, width);
  g_assert_cmpint(size[1], ==, height);
  g_assert_cmpint(atk_component_contains(ATK_COMPONENT(object), x, y, coordinates),
                  ==, width > 0 && height > 0);
  g_assert_false(atk_component_contains(ATK_COMPONENT(object), x + width, y, coordinates));
  g_assert_false(atk_component_contains(ATK_COMPONENT(object), x, y + height, coordinates));
}

static void assert_geometry_unavailable(AtkObject* object) {
  const AtkCoordType coordinates[] = {ATK_XY_PARENT, ATK_XY_WINDOW, ATK_XY_SCREEN};
  for (const auto coord : coordinates) {
    assert_extents(object, coord, -1, -1, -1, -1);
    g_autoptr(AtkObject) hit = atk_component_ref_accessible_at_point(
        ATK_COMPONENT(object), 1, 2, coord);
    g_assert_null(hit);
    atk_component_get_extents(ATK_COMPONENT(object), nullptr, nullptr, nullptr, nullptr, coord);
  }
}

static void assert_hit(AtkObject* parent, AtkObject* child,
                       AtkCoordType coordinates, gint x, gint y) {
  g_autoptr(AtkObject) hit = atk_component_ref_accessible_at_point(
      ATK_COMPONENT(parent), x, y, coordinates);
  g_assert_true(hit == child);
}

static void test_node_geometry(FlEngine* engine) {
  g_autoptr(GtkWidget) toplevel = GTK_WIDGET(g_object_ref_sink(gtk_window_new(GTK_WINDOW_TOPLEVEL)));
  GtkWidget* fixed = gtk_fixed_new();
  gtk_container_add(GTK_CONTAINER(toplevel), fixed);
  g_autoptr(GtkWidget) widget = new_bound_view(engine);
  gtk_widget_set_size_request(widget, 120, 90);
  gtk_fixed_put(GTK_FIXED(fixed), widget, 30, 40);
  gtk_window_set_default_size(GTK_WINDOW(toplevel), 200, 180);
  gtk_window_move(GTK_WINDOW(toplevel), 100, 120);
  gtk_widget_show_all(toplevel);
  gdk_display_sync(gtk_widget_get_display(toplevel));
  g_assert_true(gtk_widget_get_mapped(widget));
  g_assert_true(gtk_widget_get_realized(widget));
  const gint scale = gtk_widget_get_scale_factor(widget);
  g_assert_nonnull(g_getenv("GDK_SCALE"));
  g_assert_cmpint(scale, ==, std::atoi(g_getenv("GDK_SCALE")));
  g_assert_true(scale == 1 || scale == 2);
  gint screen_x = 0, screen_y = 0;
  gdk_window_get_origin(gtk_widget_get_window(toplevel), &screen_x, &screen_y);
  g_autoptr(FlViewAccessible) accessible = FL_VIEW_ACCESSIBLE(
      g_object_ref(gtk_widget_get_accessible(widget)));
  GeometryTree tree(scale);
  tree.publish(accessible);
  g_autoptr(AtkObject) semantics = atk_object_ref_accessible_child(ATK_OBJECT(accessible), 0);
  g_autoptr(AtkObject) parent_object = atk_object_ref_accessible_child(semantics, 0);
  g_autoptr(AtkObject) child_object = atk_object_ref_accessible_child(parent_object, 0);
  g_assert_nonnull(child_object);
  FlAccessibleNode* parent = FL_ACCESSIBLE_NODE(parent_object);
  FlAccessibleNode* child = FL_ACCESSIBLE_NODE(child_object);
  g_assert_true(atk_object_get_parent(ATK_OBJECT(child)) == ATK_OBJECT(parent));

  // Preserve the exact original parent-relative and retired-ancestor assertions,
  // now with a real GTK owner and production semantics update/ancestry.
  gint relative[] = {99, 98, 97, 96};
  atk_component_get_extents(ATK_COMPONENT(child), &relative[0], &relative[1],
                            &relative[2], &relative[3], ATK_XY_PARENT);
  gint position[] = {99, 98};
  atk_component_get_position(ATK_COMPONENT(child), &position[0], &position[1], ATK_XY_PARENT);
  const gboolean contains = atk_component_contains(ATK_COMPONENT(child), 6, 8, ATK_XY_PARENT);

  // Keep both objects and the GTK-owned generation alive while only the ancestor retires.
  // Its unavailable geometry must not become a usable child rectangle.
  fl_accessible_node_retire(parent);
  g_assert_false(fl_accessible_node_is_live(parent));
  g_assert_true(fl_accessible_node_is_live(child));
  gint screen[] = {99, 98, 97, 96}, window[] = {99, 98, 97, 96};
  atk_component_get_extents(ATK_COMPONENT(child), &screen[0], &screen[1],
                            &screen[2], &screen[3], ATK_XY_SCREEN);
  atk_component_get_extents(ATK_COMPONENT(child), &window[0], &window[1],
                            &window[2], &window[3], ATK_XY_WINDOW);
  gint size[] = {99, 98};
  atk_component_get_size(ATK_COMPONENT(child), &size[0], &size[1]);
  const gboolean retired_contains = atk_component_contains(ATK_COMPONENT(child), 6, 8, ATK_XY_WINDOW);
  // Preserve every observation before the first assertion can terminate the test.
  std::printf("ENGINE_ACCESSIBLE_NODE_GEOMETRY_OBSERVED parent=%d,%d,%d,%d position=%d,%d contains=%d retired_screen=%d,%d,%d,%d retired_window=%d,%d,%d,%d retired_size=%d,%d retired_contains=%d\n",
              relative[0], relative[1], relative[2], relative[3], position[0], position[1], contains,
              screen[0], screen[1], screen[2], screen[3], window[0], window[1], window[2], window[3],
              size[0], size[1], retired_contains);
  std::fflush(stdout);
  g_assert_cmpint(relative[0], ==, 5);
  g_assert_cmpint(relative[1], ==, 7);
  g_assert_cmpint(relative[2], ==, 20);
  g_assert_cmpint(relative[3], ==, 10);
  g_assert_cmpint(position[0], ==, 5);
  g_assert_cmpint(position[1], ==, 7);
  g_assert_true(contains);
  for (guint i = 0; i < 4; i++) {
    g_assert_cmpint(screen[i], ==, -1);
    g_assert_cmpint(window[i], ==, -1);
  }
  g_assert_cmpint(size[0], ==, -1);
  g_assert_cmpint(size[1], ==, -1);
  g_assert_false(retired_contains);
  std::puts("ENGINE_ACCESSIBLE_NODE_GEOMETRY=pass unit=real-node parent_relative=true retired_ancestor=unavailable position_size=consistent contains=closed");
  std::fflush(stdout);

  fl_view_accessible_reset(accessible);
  tree.publish(accessible);
  g_clear_object(&semantics);
  g_clear_object(&parent_object);
  g_clear_object(&child_object);
  semantics = atk_object_ref_accessible_child(ATK_OBJECT(accessible), 0);
  parent_object = atk_object_ref_accessible_child(semantics, 0);
  child_object = atk_object_ref_accessible_child(parent_object, 0);
  parent = FL_ACCESSIBLE_NODE(parent_object);
  child = FL_ACCESSIBLE_NODE(child_object);
  assert_extents(ATK_OBJECT(accessible), ATK_XY_PARENT, 30, 40, 120, 90);
  assert_extents(ATK_OBJECT(accessible), ATK_XY_WINDOW, 30, 40, 120, 90);
  assert_extents(ATK_OBJECT(accessible), ATK_XY_SCREEN, screen_x + 30, screen_y + 40, 120, 90);
  g_assert_true(atk_component_grab_focus(ATK_COMPONENT(accessible)));
  g_assert_true(gtk_widget_is_focus(widget));
  // A semantics view is not a toplevel; ATK cannot move/resize its GTK container.
  g_assert_false(atk_component_set_position(ATK_COMPONENT(accessible), 1, 2, ATK_XY_SCREEN));
  g_assert_false(atk_component_set_size(ATK_COMPONENT(accessible), 3, 4));
  g_assert_false(atk_component_set_extents(ATK_COMPONENT(accessible), 1, 2, 3, 4, ATK_XY_SCREEN));
  assert_extents(child_object, ATK_XY_PARENT, 5, 7, 20, 10);
  assert_extents(child_object, ATK_XY_WINDOW, 75, 97, 20, 10);
  assert_extents(child_object, ATK_XY_SCREEN, screen_x + 75, screen_y + 97, 20, 10);
  assert_hit(parent_object, child_object, ATK_XY_PARENT, 46, 58);
  assert_hit(parent_object, child_object, ATK_XY_WINDOW, 76, 98);
  assert_hit(parent_object, child_object, ATK_XY_SCREEN, screen_x + 76, screen_y + 98);
  assert_hit(ATK_OBJECT(accessible), semantics, ATK_XY_PARENT, 76, 98);
  assert_hit(semantics, parent_object, ATK_XY_PARENT, 46, 58);

  const FlutterRect original_rect = tree.child.rect;
  const FlutterTransformation original_child = tree.child.transform;
  const FlutterTransformation original_parent = tree.parent.transform;
  tree.child.rect = {0.2, 0.3, 10.4, 6.8};
  tree.child.transform.transX = 5.25;
  tree.child.transform.transY = 7.5;
  tree.publish(accessible);
  assert_extents(child_object, ATK_XY_PARENT, 5, 7, 11, 8);
  tree.child.rect = original_rect;
  tree.child.transform = original_child;
  tree.child.transform.skewX = 0.5;
  tree.child.transform.skewY = 0.25;
  tree.publish(accessible);
  assert_extents(child_object, ATK_XY_PARENT, 5, 7, 25, 15);
  tree.child.transform = original_child;
  tree.child.transform.scaleX = tree.child.transform.scaleY = 0;
  tree.child.transform.skewX = -1;
  tree.child.transform.skewY = 1;
  tree.child.transform.transX = 15;
  tree.publish(accessible);
  assert_extents(child_object, ATK_XY_PARENT, 5, 7, 10, 20);
  tree.child.transform = original_child;
  tree.child.transform.scaleX = -1;
  tree.child.transform.transX = 25;
  tree.publish(accessible);
  assert_extents(child_object, ATK_XY_PARENT, 5, 7, 20, 10);

  // An ancestor rotation and inverse child rotation cancel before the AABB.
  // Adding already-rounded parent boxes cannot produce these coordinates.
  tree.parent.transform.scaleX = tree.parent.transform.scaleY = 0;
  tree.parent.transform.skewX = -1;
  tree.parent.transform.skewY = 1;
  tree.child.transform = original_child;
  tree.child.transform.scaleX = tree.child.transform.scaleY = 0;
  tree.child.transform.skewX = 1;
  tree.child.transform.skewY = -1;
  tree.publish(accessible);
  assert_extents(parent_object, ATK_XY_WINDOW, -10, 90, 80, 100);
  assert_extents(child_object, ATK_XY_PARENT, 73, 5, 20, 10);
  assert_extents(child_object, ATK_XY_WINDOW, 63, 95, 20, 10);
  tree.parent.transform = original_parent;
  tree.child.transform = identity_transform();
  tree.child.transform.pers0 = 0.01;
  tree.publish(accessible);
  assert_extents(child_object, ATK_XY_PARENT, 0, 0, 17, 10);

  for (guint invalid = 0; invalid < 9; invalid++) {
    tree.child.rect = original_rect;
    tree.child.transform = original_child;
    tree.parent.transform = original_parent;
    switch (invalid) {
      case 0: tree.child.rect.left = std::numeric_limits<double>::quiet_NaN(); break;
      case 1: tree.child.transform.transX = std::numeric_limits<double>::infinity(); break;
      case 2: tree.child.rect.right = -1; break;
      case 3: tree.child.transform = {}; break;
      case 4:
        tree.child.transform.pers0 = 0.1;
        tree.child.transform.pers2 = -1;
        break;
      case 5: tree.child.rect = {-1e20, 0, 1e20, 10}; break;
      case 6: tree.child.transform.transX = G_MAXINT; break;
      case 7:
        tree.child.rect = {-G_MAXINT, 0, G_MAXINT, 10};
        break;
      case 8:
        tree.parent.transform.scaleX = 1e200;
        tree.child.transform.scaleX = 1e200;
        break;
    }
    tree.publish(accessible);
    assert_geometry_unavailable(child_object);
  }
  tree.child.rect = original_rect;
  tree.child.transform = original_child;
  tree.parent.transform = original_parent;
  tree.publish(accessible);
  fl_accessible_node_set_parent(child, nullptr, 0);
  assert_geometry_unavailable(child_object);
  tree.publish(accessible);
  g_autoptr(GPtrArray) empty = g_ptr_array_new();
  fl_accessible_node_set_children(parent, empty);
  assert_geometry_unavailable(child_object);
  tree.publish(accessible);
  g_autoptr(GtkWidget) foreign_widget = new_generation_widget();
  g_autoptr(FlSemanticsGeneration) foreign_generation = fl_semantics_generation_new(
      GTK_ACCESSIBLE(gtk_widget_get_accessible(foreign_widget)), engine, 7);
  g_autoptr(FlAccessibleNode) foreign_parent = fl_accessible_node_new(foreign_generation, 9);
  g_autoptr(GPtrArray) foreign_children = g_ptr_array_new();
  g_ptr_array_add(foreign_children, child);
  fl_accessible_node_set_children(foreign_parent, foreign_children);
  fl_accessible_node_set_parent(child, ATK_OBJECT(foreign_parent), 0);
  assert_geometry_unavailable(child_object);
  tree.publish(accessible);
  g_autoptr(GPtrArray) cycle_children = g_ptr_array_new();
  g_ptr_array_add(cycle_children, parent);
  fl_accessible_node_set_children(child, cycle_children);
  fl_accessible_node_set_parent(parent, child_object, 0);
  assert_geometry_unavailable(child_object);
  fl_accessible_node_set_children(child, empty);
  tree.publish(accessible);
  gtk_widget_hide(widget);
  g_assert_false(atk_component_grab_focus(ATK_COMPONENT(accessible)));
  assert_geometry_unavailable(ATK_OBJECT(accessible));
  assert_geometry_unavailable(child_object);
  gtk_widget_show_all(widget);
  assert_extents(child_object, ATK_XY_PARENT, 5, 7, 20, 10);

  g_assert_true(atk_action_do_action(ATK_ACTION(parent), 0));
  g_assert_true(atk_action_do_action(ATK_ACTION(child), 0));
  TreeRevocation context = {engine, parent, child, 0, accessible, 5};
  g_signal_connect(parent, "state-change::defunct", G_CALLBACK(probe_tree_revocation), &context);
  g_signal_connect(child, "state-change::defunct", G_CALLBACK(probe_tree_revocation), &context);
  const guint dispatches = engine->dispatches;
  gtk_widget_destroy(toplevel);
  g_assert_cmpuint(context.notifications, ==, 2);
  g_assert_cmpuint(engine->dispatches, ==, dispatches);
  g_assert_null(gtk_accessible_get_widget(GTK_ACCESSIBLE(accessible)));
  g_assert_false(atk_component_grab_focus(ATK_COMPONENT(accessible)));
  assert_geometry_unavailable(ATK_OBJECT(accessible));
  assert_geometry_unavailable(child_object);
  g_assert_false(fl_view_accessible_bind_engine(accessible, engine, 7));
  tree.publish(accessible);
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(accessible)), ==, 0);
  g_signal_handlers_disconnect_by_data(parent, &context);
  g_signal_handlers_disconnect_by_data(child, &context);
  std::puts("ENGINE_ACCESSIBLE_WIDGET_GEOMETRY=pass owner=gtk-bound early_binding=closed transforms=full parent_hit_test=consistent invalid=closed hidden=unavailable teardown=revoked");
  std::fflush(stdout);
}

static void retire_text(AtkObject* object, TextRetirement* context) {
  context->notifications++;
  if (context->dispose) {
    g_object_run_dispose(G_OBJECT(object));
  } else {
    fl_accessible_node_retire(FL_ACCESSIBLE_NODE(object));
  }
}

static void test_text_field(FlEngine* engine) {
  g_autoptr(GtkWidget) widget = new_generation_widget();
  g_autoptr(FlSemanticsGeneration) generation = fl_semantics_generation_new(
      GTK_ACCESSIBLE(gtk_widget_get_accessible(widget)), engine, 7);
  // Live edits must still send the actual standard-codec payloads in order.
  g_autoptr(FlAccessibleNode) live = fl_accessible_text_field_new(generation, 10);
  fl_accessible_node_set_value(live, "original");
  fl_accessible_node_set_text_selection(live, 2, 4);
  g_assert_cmpint(atk_text_get_character_count(ATK_TEXT(live)), ==, 8);
  gint start = -1, end = -1;
  g_autofree gchar* selected = atk_text_get_selection(ATK_TEXT(live), 0, &start, &end);
  g_assert_cmpstr(selected, ==, "ig");
  g_assert_cmpint(start, ==, 2);
  g_assert_cmpint(end, ==, 4);
  gint position = 2;
  guint dispatches = engine->dispatches;
  atk_editable_text_insert_text(ATK_EDITABLE_TEXT(live), "x", 1, &position);
  g_assert_cmpint(position, ==, 3);
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 2);
  g_assert_cmpstr(engine->last_text, ==, "orxiginal");
  g_assert_cmpint(engine->selection_base, ==, 3);
  g_assert_cmpint(engine->selection_extent, ==, 3);
  atk_editable_text_delete_text(ATK_EDITABLE_TEXT(live), 0, 1);
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 4);
  g_assert_cmpstr(engine->last_text, ==, "rxiginal");
  g_assert_cmpint(engine->selection_base, ==, 0);
  g_assert_cmpint(engine->selection_extent, ==, 0);
  g_assert_true(atk_text_set_caret_offset(ATK_TEXT(live), 2));
  fl_accessible_node_set_text_selection(live, 2, 2);
  g_assert_true(atk_text_add_selection(ATK_TEXT(live), 1, 3));
  fl_accessible_node_set_text_selection(live, 1, 3);
  g_assert_true(atk_text_remove_selection(ATK_TEXT(live), 0));
  g_assert_cmpint(engine->selection_base, ==, 3);
  g_assert_cmpint(engine->selection_extent, ==, 3);

  for (guint dispose = 0; dispose < 2; dispose++) {
    g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(generation, 10);
    fl_accessible_node_set_value(text, "original");
    fl_accessible_node_set_text_selection(text, 1, 3);
    TextRetirement context = {engine, dispose != 0, 0};
    g_signal_connect(text, "state-change::defunct",
                     G_CALLBACK(+[](AtkObject* object, const gchar*, gboolean state,
                                    TextRetirement* context) {
                       g_assert_true(state);
                       context->notifications++;
                       assert_text_field_closed(FL_ACCESSIBLE_NODE(object), context->engine);
                     }), &context);
    if (dispose) {
      g_object_run_dispose(G_OBJECT(text));
      g_object_run_dispose(G_OBJECT(text));
    } else {
      fl_accessible_node_retire(text);
      fl_accessible_node_retire(text);
    }
    g_assert_cmpuint(context.notifications, ==, 1);
    assert_text_field_closed(text, engine);
    g_signal_handlers_disconnect_by_data(text, &context);
  }

  // GTK signals are synchronous: retirement/disposal must stop the admitted edit.
  for (guint dispose = 0; dispose < 2; dispose++) {
    for (guint remove = 0; remove < 2; remove++) {
      g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(generation, 10);
      fl_accessible_node_set_value(text, "original");
      TextRetirement context = {engine, dispose != 0, 0};
      g_signal_connect(text, remove ? "text-remove" : "text-insert",
                       G_CALLBACK(+[](AtkObject* object, gint, gint, const gchar*,
                                      TextRetirement* context) {
                         retire_text(object, context);
                       }), &context);
      dispatches = engine->dispatches;
      position = 2;
      if (remove) {
        atk_editable_text_delete_text(ATK_EDITABLE_TEXT(text), 0, 1);
      } else {
        atk_editable_text_insert_text(ATK_EDITABLE_TEXT(text), "x", 1, &position);
      }
      g_assert_cmpuint(context.notifications, ==, 1);
      g_assert_cmpint(position, ==, 2);
      g_assert_cmpuint(engine->dispatches, ==, dispatches);
      assert_text_field_closed(text, engine);
      g_signal_handlers_disconnect_by_data(text, &context);
    }

    g_autoptr(FlAccessibleNode) selection = fl_accessible_text_field_new(generation, 10);
    TextRetirement context = {engine, dispose != 0, 0};
    guint caret_notifications = 0;
    g_signal_connect(selection, "text-selection-changed", G_CALLBACK(retire_text), &context);
    g_signal_connect(selection, "text-caret-moved",
                     G_CALLBACK(+[](AtkObject*, gint, guint* count) { (*count)++; }),
                     &caret_notifications);
    fl_accessible_node_set_text_selection(selection, 0, 2);
    g_assert_cmpuint(context.notifications, ==, 1);
    g_assert_cmpuint(caret_notifications, ==, 0);
    assert_text_field_closed(selection, engine);
    g_signal_handlers_disconnect_by_data(selection, &context);
    g_signal_handlers_disconnect_by_data(selection, &caret_notifications);

    for (guint copy = 0; copy < 2; copy++) {
      g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(generation, 10);
      fl_accessible_node_set_value(text, "original");
      engine->retire_on_dispatch = text;
      engine->dispose_on_dispatch = dispose != 0;
      dispatches = engine->dispatches;
      position = 2;
      if (copy) {
        atk_editable_text_copy_text(ATK_EDITABLE_TEXT(text), 0, 1);
      } else {
        atk_editable_text_insert_text(ATK_EDITABLE_TEXT(text), "x", 1, &position);
      }
      g_assert_null(engine->retire_on_dispatch);
      g_assert_cmpuint(engine->dispatches, ==, dispatches + 1);
      g_assert_cmpint(position, ==, 2);
      assert_text_field_closed(text, engine);
    }
  }
  // A signal may drop the caller's last reference. The admitted method owns self.
  FlAccessibleNode* unowned = fl_accessible_text_field_new(generation, 10);
  fl_accessible_node_set_value(unowned, "original");
  gpointer weak = unowned;
  g_object_add_weak_pointer(G_OBJECT(unowned), &weak);
  g_signal_connect(unowned, "text-insert",
                   G_CALLBACK(+[](AtkObject*, gint, gint, const gchar*,
                                  FlAccessibleNode** owner) {
                     g_clear_object(owner);
                   }), &unowned);
  dispatches = engine->dispatches;
  position = 2;
  atk_editable_text_insert_text(ATK_EDITABLE_TEXT(unowned), "x", 1, &position);
  g_assert_null(unowned);
  g_assert_null(weak);
  g_assert_cmpint(position, ==, 3);
  g_assert_cmpuint(engine->dispatches, ==, dispatches + 2);
  std::puts("ENGINE_ACCESSIBLE_TEXT_FIELD_RETIREMENT=pass unit=real-text-field retired_disposed=closed live_edits=allowed reentrant_buffer=closed reentrant_selection=closed reentrant_dispatch=closed caller_release=joined late_edits=refused");
}
#endif

// The one replaced boundary is explicit: observe real node dispatch calls.
extern "C" void fl_engine_dispatch_semantics_action(
    FlEngine* engine, FlutterViewId view_id, uint64_t node_id,
    FlutterSemanticsAction action, GBytes* data) {
  g_assert_cmpint(view_id, ==, 7);
  if (node_id == 9 || node_id == 11) {
    g_assert_cmpint(action, ==, kFlutterSemanticsActionTap);
    g_assert_null(data);
  } else {
    g_assert_cmpuint(node_id, ==, 10);
    g_assert_nonnull(data);
    g_autoptr(FlStandardMessageCodec) codec = fl_standard_message_codec_new();
    g_autoptr(GError) error = nullptr;
    g_autoptr(FlValue) value =
        fl_message_codec_decode_message(FL_MESSAGE_CODEC(codec), data, &error);
    g_assert_no_error(error);
    g_assert_nonnull(value);
    if (action == kFlutterSemanticsActionSetText) {
      g_assert_cmpint(fl_value_get_type(value), ==, FL_VALUE_TYPE_STRING);
      g_free(engine->last_text);
      engine->last_text = g_strdup(fl_value_get_string(value));
    } else {
      g_assert_cmpint(action, ==, kFlutterSemanticsActionSetSelection);
      g_assert_cmpint(fl_value_get_type(value), ==, FL_VALUE_TYPE_MAP);
      FlValue* base = fl_value_lookup_string(value, "base");
      FlValue* extent = fl_value_lookup_string(value, "extent");
      g_assert_nonnull(base);
      g_assert_nonnull(extent);
      g_assert_cmpint(fl_value_get_type(base), ==, FL_VALUE_TYPE_INT);
      g_assert_cmpint(fl_value_get_type(extent), ==, FL_VALUE_TYPE_INT);
      engine->selection_base = fl_value_get_int(base);
      engine->selection_extent = fl_value_get_int(extent);
    }
  }
  engine->dispatches++;
#if !defined(LEGACY_BASELINE)
  FlAccessibleNode* retire = engine->retire_on_dispatch;
  engine->retire_on_dispatch = nullptr;
  if (retire != nullptr) {
    if (engine->dispose_on_dispatch) {
      g_object_run_dispose(G_OBJECT(retire));
    } else {
      fl_accessible_node_retire(retire);
    }
  }
#endif
}

int main() {
  g_log_set_always_fatal(static_cast<GLogLevelFlags>(G_LOG_FATAL_MASK | G_LOG_LEVEL_CRITICAL));
#if !defined(LEGACY_BASELINE)
  test_gtk_widget_lifetime();
#endif
  g_autoptr(FlEngine) engine = FL_ENGINE(g_object_new(fl_engine_get_type(), nullptr));
#if defined(LEGACY_BASELINE)
  g_autoptr(FlAccessibleNode) node = fl_accessible_node_new(engine, 7, 9);
#else
  g_autoptr(GtkWidget) widget = new_generation_widget();
  g_autoptr(FlSemanticsGeneration) generation = fl_semantics_generation_new(
      GTK_ACCESSIBLE(gtk_widget_get_accessible(widget)), engine, 7);
  g_autoptr(FlAccessibleNode) node = fl_accessible_node_new(generation, 9);
#endif
  g_autoptr(AtkObject) parent = ATK_OBJECT(g_object_new(ATK_TYPE_OBJECT, nullptr));
  fl_accessible_node_set_parent(node, parent, 0);
  fl_accessible_node_set_actions(node, kFlutterSemanticsActionTap);
#if defined(LEGACY_BASELINE)
  fl_accessible_node_set_extents(node, 1, 2, 3, 4);
#else
  FlutterRect rect = {1, 2, 4, 6};
  FlutterTransformation transform = identity_transform();
  fl_accessible_node_set_geometry(node, &rect, &transform);
#endif
  g_assert_true(atk_action_do_action(ATK_ACTION(node), 0));
  g_assert_cmpuint(engine->dispatches, ==, 1);
  g_clear_object(&parent);
  g_assert_null(atk_object_get_parent(ATK_OBJECT(node)));

#if defined(LEGACY_BASELINE)
  // Exact old node still dispatches after its tree parent has disappeared.
  g_assert_true(atk_action_do_action(ATK_ACTION(node), 0));
  g_assert_cmpuint(engine->dispatches, ==, 2);
  std::puts("ENGINE_ACCESSIBLE_RETIREMENT_BASELINE=observed parent=gone engine=live action=dispatched");
#else
  fl_accessible_node_retire(node);
  fl_accessible_node_retire(node);
  g_assert_false(atk_action_do_action(ATK_ACTION(node), 0));
  g_assert_cmpint(atk_action_get_n_actions(ATK_ACTION(node)), ==, 0);
  g_assert_null(atk_action_get_name(ATK_ACTION(node), 0));
  fl_accessible_node_perform_action(node, kFlutterSemanticsActionTap, nullptr);
  g_assert_cmpuint(engine->dispatches, ==, 1);
  g_autoptr(AtkStateSet) state = atk_object_ref_state_set(ATK_OBJECT(node));
  g_assert_true(atk_state_set_contains_state(state, ATK_STATE_DEFUNCT));
  g_assert_false(atk_state_set_contains_state(state, ATK_STATE_SHOWING));
  gint x = 99, y = 98, width = 97, height = 96;
  atk_component_get_extents(ATK_COMPONENT(node), &x, &y, &width, &height, ATK_XY_SCREEN);
  g_assert_cmpint(x, ==, -1);
  g_assert_cmpint(y, ==, -1);
  g_assert_cmpint(width, ==, -1);
  g_assert_cmpint(height, ==, -1);

  // Late metadata writes must never restore the revoked dispatch authority.
  fl_accessible_node_set_actions(node, kFlutterSemanticsActionTap);
  fl_accessible_node_perform_action(node, kFlutterSemanticsActionTap, nullptr);
  g_assert_false(atk_action_do_action(ATK_ACTION(node), 0));
  g_assert_cmpuint(engine->dispatches, ==, 1);

  g_autoptr(FlAccessibleNode) fresh = fl_accessible_node_new(generation, 9);
  fl_accessible_node_set_actions(fresh, kFlutterSemanticsActionTap);
  g_assert_true(atk_action_do_action(ATK_ACTION(fresh), 0));
  g_assert_cmpuint(engine->dispatches, ==, 2);

  // Exercise synchronous retirement from the real children-changed callback.
  g_autoptr(FlAccessibleNode) reentrant = fl_accessible_node_new(generation, 9);
  g_autoptr(GPtrArray) children = g_ptr_array_new_with_free_func(g_object_unref);
  g_ptr_array_add(children, g_object_ref(fresh));
  fl_accessible_node_set_children(reentrant, children);
  g_signal_connect(reentrant, "children-changed::remove",
                   G_CALLBACK(retire_on_child_removal), nullptr);
  g_autoptr(GPtrArray) empty = g_ptr_array_new();
  fl_accessible_node_set_children(reentrant, empty);
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(reentrant)), ==, 0);
  g_assert_false(atk_action_do_action(ATK_ACTION(reentrant), 0));
  g_assert_cmpuint(engine->dispatches, ==, 2);
  g_object_run_dispose(G_OBJECT(node));
  fl_accessible_node_retire(node);
  fl_accessible_node_set_actions(node, kFlutterSemanticsActionTap);
  fl_accessible_node_set_parent(node, ATK_OBJECT(fresh), 0);
  fl_accessible_node_set_children(node, children);
  g_assert_false(atk_action_do_action(ATK_ACTION(node), 0));
  g_assert_null(atk_object_get_parent(ATK_OBJECT(node)));
  g_assert_cmpint(atk_object_get_n_accessible_children(ATK_OBJECT(node)), ==, 0);
  g_assert_cmpint(atk_action_get_n_actions(ATK_ACTION(node)), ==, 0);
  g_assert_cmpuint(engine->dispatches, ==, 2);
  std::puts("ENGINE_ACCESSIBLE_RETIREMENT=pass unit=real-node boundary=recording-engine idempotent=true stale=refused fresh=allowed geometry=defunct reentrant=true disposed=true");
  std::fflush(stdout);
  test_root(engine);
  test_tree_revocation(engine);
  test_generation(engine);
  test_text_field(engine);
  test_node_geometry(engine);
#endif
  return 0;
}
