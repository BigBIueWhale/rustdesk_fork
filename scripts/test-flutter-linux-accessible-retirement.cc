// Executes the real node, root and text-field implementations with a recording
// engine boundary. This is an ATK/GObject unit test, not a running Flutter engine,
// GtkWidget/view teardown test, privileged receiver test, or app replay.
#include "flutter/shell/platform/linux/fl_accessible_node.h"
#include "flutter/shell/platform/linux/fl_accessible_text_field.h"
#include "flutter/shell/platform/linux/fl_view_accessible.h"
#include "flutter/shell/platform/linux/public/flutter_linux/fl_standard_message_codec.h"
#include "flutter/shell/platform/linux/public/flutter_linux/fl_value.h"

#include <cstdio>

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
  root.child_count = siblings ? 2 : 1;
  root.children_in_traversal_order = children;
  FlutterSemanticsNode2 child = {};
  child.id = 9;
  child.label = "child";
  child.value = "";
  child.flags2 = &flags;
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
}

static void test_tree_revocation(FlEngine* engine) {
  for (guint operation = 0; operation < 3; operation++) {
    g_autoptr(FlViewAccessible) accessible = fl_view_accessible_new(engine, 7);
    update_tree(accessible, "whole tree", TRUE);
    g_autoptr(AtkObject) root = atk_object_ref_accessible_child(ATK_OBJECT(accessible), 0);
    g_assert_nonnull(root);
    g_autoptr(AtkObject) first = atk_object_ref_accessible_child(root, 0);
    g_autoptr(AtkObject) second = atk_object_ref_accessible_child(root, 1);
    g_assert_nonnull(first);
    g_assert_nonnull(second);
    g_assert_true(atk_action_do_action(ATK_ACTION(first), 0));
    g_assert_true(atk_action_do_action(ATK_ACTION(second), 0));
    TreeRevocation context = {engine, FL_ACCESSIBLE_NODE(first), FL_ACCESSIBLE_NODE(second), 0};
    g_signal_connect(first, "state-change::defunct", G_CALLBACK(probe_tree_revocation), &context);
    g_signal_connect(second, "state-change::defunct", G_CALLBACK(probe_tree_revocation), &context);
    const guint dispatches = engine->dispatches;
    switch (operation) {
      case 0:
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
  }
  std::puts("ENGINE_ACCESSIBLE_TREE_REVOCATION=pass unit=real-root first_notification=closed indexed_direct=refused reset_retire_dispose=closed");
  std::fflush(stdout);
}

static void test_root(FlEngine* engine) {
  const guint dispatches = engine->dispatches;
  g_autoptr(FlViewAccessible) accessible = fl_view_accessible_new(engine, 7);
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

static void retire_text(AtkObject* object, TextRetirement* context) {
  context->notifications++;
  if (context->dispose) {
    g_object_run_dispose(G_OBJECT(object));
  } else {
    fl_accessible_node_retire(FL_ACCESSIBLE_NODE(object));
  }
}

static void test_text_field(FlEngine* engine) {
  // Live edits must still send the actual standard-codec payloads in order.
  g_autoptr(FlAccessibleNode) live = fl_accessible_text_field_new(engine, 7, 10);
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
    g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(engine, 7, 10);
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
      g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(engine, 7, 10);
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

    g_autoptr(FlAccessibleNode) selection = fl_accessible_text_field_new(engine, 7, 10);
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
      g_autoptr(FlAccessibleNode) text = fl_accessible_text_field_new(engine, 7, 10);
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
  FlAccessibleNode* unowned = fl_accessible_text_field_new(engine, 7, 10);
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
  g_autoptr(FlEngine) engine = FL_ENGINE(g_object_new(fl_engine_get_type(), nullptr));
  g_autoptr(FlAccessibleNode) node = fl_accessible_node_new(engine, 7, 9);
  g_autoptr(AtkObject) parent = ATK_OBJECT(g_object_new(ATK_TYPE_OBJECT, nullptr));
  fl_accessible_node_set_parent(node, parent, 0);
  fl_accessible_node_set_actions(node, kFlutterSemanticsActionTap);
  fl_accessible_node_set_extents(node, 1, 2, 3, 4);
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

  g_autoptr(FlAccessibleNode) fresh = fl_accessible_node_new(engine, 7, 9);
  fl_accessible_node_set_actions(fresh, kFlutterSemanticsActionTap);
  g_assert_true(atk_action_do_action(ATK_ACTION(fresh), 0));
  g_assert_cmpuint(engine->dispatches, ==, 2);

  // Exercise synchronous retirement from the real children-changed callback.
  g_autoptr(FlAccessibleNode) reentrant = fl_accessible_node_new(engine, 7, 9);
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
  test_text_field(engine);
#endif
  return 0;
}
