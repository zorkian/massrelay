#include <os/log.h>
#include <stdbool.h>

// Use the SDK macro so Clang supplies its logging argument layout.
void massrelay_oslog_write(os_log_t log, bool error, const char *text) {
    if (error) {
        os_log_error(log, "%{public}s", text);
    } else {
        os_log(log, "%{public}s", text);
    }
}
