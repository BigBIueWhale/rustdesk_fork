#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "my_application.h"

#define RUSTDESK_LIB_PATH "$ORIGIN/lib/librustdesk.so"
typedef bool (*RustDeskCoreMain)();
bool gIsConnectionManager = false;

bool flutter_rustdesk_core_main(bool* should_start_ui) {
   if (!should_start_ui) {
      fprintf(stderr, "RustDesk core UI decision output is null\n");
      return false;
   }
   void* librustdesk = dlopen(RUSTDESK_LIB_PATH, RTLD_NOW | RTLD_LOCAL);
   if (!librustdesk) {
      fprintf(stderr, "Failed to load \"%s\"\n", RUSTDESK_LIB_PATH);
      const char* error;
      if ((error = dlerror()) != nullptr) {
        fprintf(stderr, "%s\n", error);
      }
     return false;
   }
   dlerror();
   auto core_main = (RustDeskCoreMain) dlsym(librustdesk,"rustdesk_core_main");
   const char* error;
   if ((error = dlerror()) != nullptr) {
       fprintf(stderr, "Program entry \"rustdesk_core_main\" is not found: %s\n", error);
       return false;
   }
   *should_start_ui = core_main();
   return true;
}

int main(int argc, char** argv) {
  bool should_start_ui = false;
  if (!flutter_rustdesk_core_main(&should_start_ui)) {
      return EXIT_FAILURE;
  }
  if (!should_start_ui) {
      return EXIT_SUCCESS;
  }
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--cm") == 0) {
      gIsConnectionManager = true;
    }
  }
  g_autoptr(MyApplication) app = my_application_new();
  return g_application_run(G_APPLICATION(app), argc, argv);
}
