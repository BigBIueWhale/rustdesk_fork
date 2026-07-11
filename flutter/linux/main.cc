#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "my_application.h"

#define RUSTDESK_LIB_PATH "$ORIGIN/lib/librustdesk.so"
typedef bool (*RustDeskCoreMain)();
bool gIsConnectionManager = false;

bool flutter_rustdesk_core_main() {
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
   return core_main();
}

int main(int argc, char** argv) {
  if (!flutter_rustdesk_core_main()) {
      return 1;
  }
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--cm") == 0) {
      gIsConnectionManager = true;
    }
  }
  g_autoptr(MyApplication) app = my_application_new();
  return g_application_run(G_APPLICATION(app), argc, argv);
}
