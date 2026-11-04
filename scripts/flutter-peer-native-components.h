/* Read-only observations of the real viewer; the outer stage authenticates /app
 * and mounts it read-only. No candidate library is loaded into this observer. */
#include <sys/statvfs.h>
#include <sys/sysmacros.h>

static const char *const native_component_paths[] = {
    "/app/bundle/rustdesk",
    "/app/bundle/lib/libapp.so",
    "/app/bundle/lib/librustdesk.so",
    "/app/bundle/lib/libflutter_linux_gtk.so",
    "/app/bundle/lib/libdesktop_drop_plugin.so",
    "/app/bundle/lib/libdesktop_multi_window_plugin.so",
    "/app/bundle/lib/libflutter_custom_cursor_plugin.so",
    "/app/bundle/lib/libscreen_retriever_plugin.so",
    "/app/bundle/lib/libtexture_rgba_renderer_plugin.so",
    "/app/bundle/lib/liburl_launcher_linux_plugin.so",
    "/app/bundle/lib/libwindow_manager_plugin.so",
    "/app/bundle/lib/libwindow_size_plugin.so",
};
#define NATIVE_COMPONENT_COUNT (sizeof(native_component_paths) / sizeof(native_component_paths[0]))
_Static_assert(NATIVE_COMPONENT_COUNT == 12U, "review the manifested component inventory");

/* 0: every file has an executable mapping; 1: wrong identity; 2: absent mapping;
 * -1: observation failed. Controls must get their specific refusal, not an I/O error. */
static int native_component_snapshot(int process, const char *const *paths,
                                     const struct stat *expected, unsigned int phase) {
    unsigned int executable[NATIVE_COMPONENT_COUNT] = {0};
    char line[8192];
    size_t total = 0U, lines = 0U;
    int descriptor = openat(process, "maps", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return -1;
    FILE *maps = fdopen(descriptor, "r");
    if (maps == NULL) {
        close(descriptor);
        return -1;
    }
    int result = -1;
    while (fgets(line, sizeof(line), maps) != NULL) {
        size_t length = strlen(line);
        unsigned long long first, last, offset, inode;
        unsigned int device_major, device_minor;
        char permissions[5] = {0};
        int consumed = 0;
        if (length == 0U || line[length - 1U] != '\n' || ++lines > 8192U ||
            (total += length) > 2U * 1024U * 1024U ||
            sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n", &first, &last,
                   permissions, &offset, &device_major, &device_minor, &inode, &consumed) != 7 ||
            consumed <= 0 || (size_t)consumed > length || first >= last ||
            strlen(permissions) != 4U) goto out;
        line[length - 1U] = '\0';
        const char *path = line + consumed;
        const char *basename = strrchr(path, '/');
        for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i) {
            const char *wanted = strrchr(paths[i], '/') + 1;
            if (strcmp(path, paths[i]) != 0) {
                /* Reject the same component name from another path or a deleted inode. */
                if (basename != NULL && strncmp(basename + 1, wanted, strlen(wanted)) == 0 &&
                    (basename[1 + strlen(wanted)] == '\0' || basename[1 + strlen(wanted)] == ' ')) {
                    if (phase != 0U) fprintf(stderr, "FLUTTER_PEER_NATIVE_COMPONENT_WRONG_PATH path=%s\n", path);
                    result = 1;
                    goto out;
                }
                continue;
            }
            if (inode != (unsigned long long)expected[i].st_ino ||
                device_major != major(expected[i].st_dev) ||
                device_minor != minor(expected[i].st_dev) ||
                (permissions[1] == 'w' && permissions[2] == 'x')) {
                if (phase != 0U) fprintf(stderr, "FLUTTER_PEER_NATIVE_COMPONENT_WRONG_IDENTITY path=%s\n", path);
                result = 1;
                goto out;
            }
            if (permissions[0] == 'r' && permissions[1] == '-' && permissions[2] == 'x')
                executable[i] += 1U;
        }
    }
    if (ferror(maps) || !feof(maps) || lines == 0U) goto out;
    result = 0;
    for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i) {
        if (executable[i] == 0U) {
            if (phase != 0U) fprintf(stderr, "FLUTTER_PEER_NATIVE_COMPONENT_UNMAPPED path=%s\n", paths[i]);
            result = 2;
        }
    }
    if (result == 0 && phase != 0U) {
        for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i)
            printf("FLUTTER_PEER_NATIVE_COMPONENT phase=%u path=%s device=%x:%x inode=%llu "
                   "executable_mappings=%u\n", phase, paths[i], major(expected[i].st_dev),
                   minor(expected[i].st_dev), (unsigned long long)expected[i].st_ino, executable[i]);
    }
out:
    if (fclose(maps) != 0) result = -1;
    return result;
}

static int exercise_native_components(Display *display, const ViewerWindow *viewer,
                                      SourceHistory *history, const char *start,
                                      const ConnectionIdentity *connection,
                                      const ProcessResources *baseline) {
    int files[NATIVE_COMPONENT_COUNT], process = -1, pidfd = -1, result = -1;
    struct stat expected[NATIVE_COMPONENT_COUNT];
    const char *paths[NATIVE_COMPONENT_COUNT];
    char process_path[64], executable_path[PATH_MAX], state;
    ConnectionIdentity after = {{0}, {0}, 0UL};
    ProcessResources resources = {0};
    uint64_t fresh, age;
    for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i) {
        files[i] = -1;
        paths[i] = native_component_paths[i];
    }
    int length = snprintf(process_path, sizeof(process_path), "/proc/%lu", viewer->pid);
    if (length <= 0 || (size_t)length >= sizeof(process_path)) goto out;
    process = open(process_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    pidfd = (int)syscall(SYS_pidfd_open, (pid_t)viewer->pid, 0U);
    if (process < 0 || pidfd < 0 || !viewer_pidfd_alive(pidfd) ||
        viewer_process_state(process, viewer->pid, start, &state) != 0) goto out;
    ssize_t bytes = readlinkat(process, "exe", executable_path, sizeof(executable_path) - 1U);
    if (bytes <= 0 || (size_t)bytes >= sizeof(executable_path) - 1U) goto out;
    executable_path[bytes] = '\0';
    if (strcmp(executable_path, paths[0]) != 0) goto out;
    for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i) {
        struct statvfs filesystem;
        files[i] = open(paths[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (files[i] < 0 || fstat(files[i], &expected[i]) != 0 ||
            !S_ISREG(expected[i].st_mode) || expected[i].st_nlink != 1 ||
            expected[i].st_size <= 0 || fstatvfs(files[i], &filesystem) != 0 ||
            (filesystem.f_flag & ST_RDONLY) == 0U) goto out;
    }
    if (native_component_snapshot(process, paths, expected, 1U) != 0) goto out;
    /* Change only the observer's expectations, never a file or process mapping. */
    expected[8].st_ino ^= 1U;
    int wrong_inode = native_component_snapshot(process, paths, expected, 0U);
    expected[8].st_ino ^= 1U;
    expected[8].st_dev ^= 1U;
    int wrong_device = native_component_snapshot(process, paths, expected, 0U);
    expected[8].st_dev ^= 1U;
    paths[8] = "/app/bundle/lib/unmapped-observer-control.so";
    int absent = native_component_snapshot(process, paths, expected, 0U);
    paths[8] = native_component_paths[8];
    if (wrong_inode != 1 || wrong_device != 1 || absent != 2 ||
        wait_for_current_frames(display, viewer, history, AUTH_WAIT_MS, 4U, &fresh, &age) != 0 ||
        native_component_snapshot(process, paths, expected, 2U) != 0 ||
        !viewer_pidfd_alive(pidfd) ||
        viewer_process_state(process, viewer->pid, start, &state) != 0 ||
        read_connection_identity(&after) != 0 || !same_connection(connection, &after) ||
        read_process_resources(viewer->pid, &resources) != 0 ||
        !resources_are_bounded(baseline, &resources)) goto out;
    for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i) {
        struct stat current;
        if (fstat(files[i], &current) != 0 || current.st_dev != expected[i].st_dev ||
            current.st_ino != expected[i].st_ino || current.st_mode != expected[i].st_mode ||
            current.st_size != expected[i].st_size || current.st_nlink != expected[i].st_nlink ||
            current.st_mtim.tv_sec != expected[i].st_mtim.tv_sec ||
            current.st_mtim.tv_nsec != expected[i].st_mtim.tv_nsec ||
            current.st_ctim.tv_sec != expected[i].st_ctim.tv_sec ||
            current.st_ctim.tv_nsec != expected[i].st_ctim.tv_nsec) goto out;
    }
    result = 0;
out:
    for (size_t i = 0U; i < NATIVE_COMPONENT_COUNT; ++i)
        if (files[i] >= 0 && close(files[i]) != 0) result = -1;
    if (pidfd >= 0 && close(pidfd) != 0) result = -1;
    if (process >= 0 && close(process) != 0) result = -1;
    if (result == 0)
        puts("FLUTTER_PEER_NATIVE_COMPONENTS_OK files=12 snapshots=2 controls=3 actual_peer=true "
             "fresh_pixels=true stable_connection=true resources=bounded");
    else fputs("FLUTTER_PEER_X11_FAIL native component identity observation\n", stderr);
    return result;
}
