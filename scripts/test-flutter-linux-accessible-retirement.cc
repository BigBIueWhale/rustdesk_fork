// Executes the real FlAccessibleNode implementation with a recording engine
// boundary. This is an ATK/GObject unit test, not a running Flutter engine,
// GtkWidget/view teardown test, privileged receiver test, or app replay.
#include "flutter/shell/platform/linux/fl_accessible_node.h"

#include <cstdio>

struct _FlEngine {
  GObject parent_instance;
  guint dispatches;
};

G_DEFINE_TYPE(FlEngine, fl_engine, G_TYPE_OBJECT)

static void fl_engine_class_init(FlEngineClass*) {}
static void fl_engine_init(FlEngine* self) { self->dispatches = 0; }

#if !defined(LEGACY_BASELINE)
static void retire_on_child_removal(AtkObject* object, guint, gpointer, gpointer) {
  fl_accessible_node_retire(FL_ACCESSIBLE_NODE(object));
}
#endif

// The one replaced boundary is explicit: observe real node dispatch calls.
extern "C" void fl_engine_dispatch_semantics_action(
    FlEngine* engine, FlutterViewId view_id, uint64_t node_id,
    FlutterSemanticsAction action, GBytes*) {
  g_assert_cmpint(view_id, ==, 7);
  g_assert_cmpuint(node_id, ==, 9);
  g_assert_cmpint(action, ==, kFlutterSemanticsActionTap);
  engine->dispatches++;
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
#endif
  return 0;
}
