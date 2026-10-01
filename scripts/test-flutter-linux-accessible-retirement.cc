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
  std::puts("ENGINE_ACCESSIBLE_RETIREMENT=pass unit=real-node boundary=recording-engine idempotent=true stale=refused fresh=allowed geometry=defunct");
#endif
  return 0;
}
