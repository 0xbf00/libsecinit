/*
 * This source code is the result of reverse engineering
 * a couple of different /usr/lib/system/libsystem_secinit.dylib
 * in macOS 10.12.6, macOS 10.13.6 and 10.14.3
 *
 * All relevant logic is 1:1 compatible with the original logic. However,
 * error handling is somewhat different. However, since the program would
 * crash in any case, this should result in no useful difference.
 *
 * This code was written so that it comes as close to Apple's code as possible
 * in the resulting disassembly. This was done to verify the logic is indeed
 * the same. You can repeat the process for yourself with a disassembler of your
 * choice (-> IDA Pro) and the excellent Diaphora.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
// errno
#include <errno.h>
// getpid()
#include <unistd.h>
// mbr_uid_to_uuid()
#include <membership.h>
// _dyld_image_count(), ...
#include <mach-o/dyld.h>
// struct mach_header definition
#include <dispatch/dispatch.h>
#include <mach-o/loader.h>

// headers that contain declarations that are not part of the public API.
// refer to the files for more information
#include "headers/os/alloc_once_private.h"
#include "headers/xpc/xpc_private.h"
#include <os/log.h>
#include <sys/errno.h>

#include "misc.h"

#define SB_CTX() ((sandbox_context*)                \
        os_alloc_once(OS_ALLOC_ONCE_KEY_LIBSECINIT, \
            sizeof(sandbox_context),                \
            NULL))

// Forward declarations. These are defined somewhere in libSystem
extern char** _NSGetProgname();
extern int __sandbox_ms(char* policyname, int call, void* args);
bool os_variant_allows_internal_security_policies(const char* subsystem);

// Variables used internally.
// Note: We define them globally because that is what Apple does.
static const char* _libsecinit_sandbox_entitlements[] = {
    "com.apple.security.app-sandbox",
    "com.apple.security.app-sandbox.optional",
    "com.apple.security.app-protection"
};

static const char* _libsecinit_dyld_envvars[] = {
    "DYLD_FRAMEWORK_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_IMAGE_SUFFIX"
};

// Definitions of data structures used internally
__attribute__((aligned(0x8))) typedef struct {
#if defined(MAC_OS_MOJAVE)
    uint8_t sandbox_candidate;
    uint8_t exit_after_init;
    uint8_t iosmac;
#elif defined(MAC_OS_HIGH_SIERRA) || defined(MAC_OS_SIERRA)
    // macOS High Sierra and older use a different layout:
    uint8_t library_validation;
    uint8_t sandbox_candidate;
    uint8_t exit_after_init;
#else
#error Unsupported or no OS version supplied.
#endif
} sandbox_flags;

typedef struct {
    dispatch_once_t dispatch_predicate;
    sandbox_flags flags;
    xpc_object_t entitlements;
    xpc_object_t server_response;
} sandbox_context;

// Ensure the used structure corresponds with the one used by the real library.
static_assert(sizeof(sandbox_context) == 0x20,
    "Padding is messing up internally used structure!");
#if defined(MAC_OS_MOJAVE)
static_assert(offsetof(sandbox_context, flags.sandbox_candidate) == 8 + 0,
    "Sandbox candidate at wrong offset.");
#else
static_assert(offsetof(sandbox_context, flags.sandbox_candidate) == 8 + 1,
    "Sandbox candidate at wrong offset.");
#endif

// Internal function declarations
static void _libsecinit_initialize_once(void* args);
static void _libsecinit_setup_secinitd_client(void);
#if defined(MAC_OS_MOJAVE)
static xpc_object_t _libsecinit_secinitd_request_send(xpc_object_t request);
#else
static xpc_object_t _libsecinit_send_request(xpc_object_t request);
#endif
static void _libsecinit_setup_app_sandbox(void);

// Function definitions
void _libsecinit_initializer()
{
    dispatch_once_f(&(SB_CTX()->dispatch_predicate),
        0,
        _libsecinit_initialize_once);
}

void _libsecinit_initialize_once(void* args)
{
    _libsecinit_setup_secinitd_client();
    _libsecinit_setup_app_sandbox();

    sandbox_context* ctx = SB_CTX();

    if (ctx->entitlements)
        xpc_release(ctx->entitlements);
    if (ctx->server_response)
        xpc_release(ctx->server_response);
}

static void _libsecinit_setup_secinitd_client()
{
    sandbox_context* ctx = SB_CTX();

    xpc_object_t entitlements = xpc_copy_entitlements_for_pid(getpid());
    if (entitlements) {
        const void* data = xpc_data_get_bytes_ptr(entitlements);
        size_t len = xpc_data_get_length(entitlements);

        ctx->entitlements = xpc_create_from_plist(data, len);
        xpc_release(entitlements);
    }

    /* Check whether the app's entitlements say it should be sandboxed. */
    if (ctx->entitlements) {
        xpc_type_t type = xpc_get_type(ctx->entitlements);
        if (type == XPC_TYPE_DICTIONARY) {
            for (size_t i = 0; i < ARR_LEN(_libsecinit_sandbox_entitlements); ++i) {
                if (xpc_dictionary_get_bool(ctx->entitlements, _libsecinit_sandbox_entitlements[i])) {
                    ctx->flags.sandbox_candidate = 1;
                    break;
                }
            }
        }
    }

    if (getenv("APP_SANDBOX_EXIT_AFTER_INIT"))
        ctx->flags.exit_after_init = 1;

#if defined(MAC_OS_MOJAVE)
    if (ctx->entitlements) {
        if (xpc_get_type(ctx->entitlements) == XPC_TYPE_DICTIONARY) {
            ctx->flags.iosmac = xpc_dictionary_get_bool(
                ctx->entitlements,
                "com.apple.private.iosmac");
        }
    }
#endif

    if (!ctx->flags.sandbox_candidate
#if defined(MAC_OS_MOJAVE)
        && !ctx->flags.iosmac
#else
        && !ctx->flags.library_validation
#endif
    ) {
        return;
    }

    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict,
        "SECINITD_MESSAGE_TYPE_KEY", 1);
    xpc_dictionary_set_uint64(dict,
        "SECINITD_REGISTRATION_MESSAGE_VERSION_NUMBER_KEY", 1);

    xpc_object_t img_paths = xpc_array_create(NULL, 0);
    xpc_object_t img_in_shared_cache = xpc_array_create(NULL, 0);

    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* name = _dyld_get_image_name(i);
        if (name) {
            xpc_array_set_string(img_paths, XPC_ARRAY_APPEND, name);

            const struct mach_header* header = _dyld_get_image_header(i);
            xpc_array_set_bool(img_in_shared_cache, XPC_ARRAY_APPEND, header->flags >> 31);
        }
    }

    xpc_dictionary_set_value(dict,
        "SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY", img_paths);
    xpc_release(img_paths);

    xpc_dictionary_set_value(dict,
        "SECINITD_REGISTRATION_MESSAGE_IMAGES_IN_SHARED_CACHE_KEY", img_in_shared_cache);
    xpc_release(img_in_shared_cache);

    xpc_object_t dyld_vars = xpc_dictionary_create(NULL, NULL, 0);
    for (size_t i = 0; i < ARR_LEN(_libsecinit_dyld_envvars); ++i) {
        char* environment_option = getenv(_libsecinit_dyld_envvars[i]);
        if (environment_option)
            xpc_dictionary_set_string(dyld_vars,
                _libsecinit_dyld_envvars[i], environment_option);
    }
    xpc_dictionary_set_value(dict,
        "SECINITD_REGISTRATION_MESSAGE_DYLD_VARIABLES_KEY", dyld_vars);
    xpc_release(dyld_vars);

    xpc_dictionary_set_bool(dict,
        "SECINITD_REGISTRATION_MESSAGE_IS_SANDBOX_CANDIDATE_KEY", ctx->flags.sandbox_candidate);

#if defined(MAC_OS_HIGH_SIERRA) || defined(MAC_OS_SIERRA)
    xpc_dictionary_set_bool(dict,
        "SECINITD_REGISTRATION_MESSAGE_LIBRARY_VALIDATION_KEY", ctx->flags.library_validation);
#endif
    xpc_dictionary_set_string(dict,
        "SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY", *_NSGetProgname());
    xpc_dictionary_set_value(dict,
        "SECINITD_REGISTRATION_MESSAGE_ENTITLEMENTS_DICT_KEY", ctx->entitlements);
    xpc_dictionary_set_bool(dict,
        "SECINITD_REGISTRATION_MESSAGE_APPSANDBOX_EXIT_AFTER_INIT", ctx->flags.exit_after_init);

#if defined(MAC_OS_MOJAVE)
    xpc_dictionary_set_bool(dict,
        "SECINITD_REGISTRATION_MESSAGE_APPIOSMAC", ctx->flags.iosmac);
#endif

    if (geteuid() != 0) {
        uuid_t uuid;
        if (0 == mbr_uid_to_uuid(geteuid(), uuid)) {
            xpc_dictionary_set_uuid(dict,
                "SECINITD_REGISTRATION_MESSAGE_UUID", uuid);
        }
    }

#if defined(MAC_OS_MOJAVE)
    if (os_variant_allows_internal_security_policies("com.apple.secinit")) {
        if (getenv("CFFIXED_USER_HOME")) {
            xpc_dictionary_set_string(dict,
                "SECINITD_REGISTRATION_MESSAGE_CFFIXED_USER_HOME", getenv("CFFIXED_USER_HOME"));
        }
    }
#endif

    XPC_TRACE("sandbox request", dict);

#if defined(MAC_OS_MOJAVE)
    xpc_object_t response = _libsecinit_secinitd_request_send(dict);
#else
    xpc_object_t response = _libsecinit_send_request(dict);
#endif
    if (!response) {
        return;
    }

    XPC_TRACE("sandbox response", response);

    if (xpc_get_type(response) != XPC_TYPE_DICTIONARY) {
        FATAL_MSG("Protocol error - Bogus reply message.");
    }

    uint64_t message_type = xpc_dictionary_get_uint64(response,
        "SECINITD_MESSAGE_TYPE_KEY");
    const char* failure_reason = xpc_dictionary_get_string(response,
        "SECINITD_REPLY_MESSAGE_FAILURE_REASON");
    const char* failure_signature = xpc_dictionary_get_string(response,
        "SECINITD_REPLY_MESSAGE_FAILURE_SIGNATURE");

    if (!failure_reason)
        failure_reason = "<no details for error>";

    if (message_type == 0x10) {
        FATAL_FORMAT("libsecinit", "%s: Some kind of sandbox registration failure.", failure_reason);
    } else if (message_type == 0x13) {
        FATAL_FORMAT("libsecinit", "%s: Some kind of internal error", failure_reason);
    } else if (message_type == 0x11) {
        if (ctx->flags.exit_after_init)
            exit(0);
        else {
            FATAL_FORMAT("libsecinit", "%s: Sandbox error - creation failed.", failure_reason);
        }
    } else {
        ctx->server_response = response;
        xpc_release(dict);
    }
}

#if defined(MAC_OS_MOJAVE)
static xpc_object_t _libsecinit_secinitd_request_send(xpc_object_t request)
#else
static xpc_object_t _libsecinit_send_request(xpc_object_t request)
#endif
{
    xpc_object_t response = NULL;

    for (int tries = 0, delay = 0;
         (tries <= 4) && !response;
         ++tries, delay += 500) {
        xpc_pipe_t pipe = xpc_pipe_create("com.apple.secinitd", 0);
        if (!pipe) {
            FATAL_MSG("Could not look up: com.apple.secinitd");
        }

        int rc = xpc_pipe_routine(pipe, request, &response);
        if (rc != 0) {
            DEBUG_FORMAT("libsecinit: xpc_pipe_routine() failed with code %d\n", rc);

            /* The original dylib has additional logging here. */
            usleep(delay);
        }

        xpc_release(pipe);
    }

    /* The original dylib has additional logging here. */
    if (!response) {
        FATAL_MSG("No secinitd response.");
    }

    return response;
}

static void _libsecinit_setup_app_sandbox()
{
    sandbox_context* ctx = SB_CTX();

    if (
        !(ctx->flags.sandbox_candidate)
#if defined(MAC_OS_MOJAVE)
        && !(ctx->flags.iosmac)
#endif
    ) {
        return;
    }

    xpc_object_t response = ctx->server_response;
    if (!response) {
        FATAL_MSG("Expected reply message from secinitd is missing.");
    }

    xpc_object_t profile_data = xpc_dictionary_get_value(response,
        "SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY");

    if (!profile_data)
        return;

    const char* container_root_path = xpc_dictionary_get_string(response,
        "SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY");
    const char* container_id = xpc_dictionary_get_string(response,
        "SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY");

    /*
     * Error handling not entirely implemented like in the original library,
     * though all other logic is identical.
     */
    if (!container_root_path || !container_id) {
        int64_t version = xpc_dictionary_get_int64(response,
            "SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY");

        if (version <= 0) {
            return;
        }

        if (!container_root_path) {
            FATAL_MSG("Reply message is missing the container root path");
        }
        if (!container_id) {
            FATAL_MSG("Reply message is missing the container ID string");
        }
    }

    const void* raw_profile_data = xpc_data_get_bytes_ptr(profile_data);
    size_t raw_profile_len = xpc_data_get_length(profile_data);

    struct sandbox_params {
        user_addr_t profile_data;
        user_size_t profile_data_len;
        user_addr_t container_root_path;
        user_size_t container_root_path_len;
        user_size_t unknown;
    };

    struct sandbox_params params = {
        .profile_data = (user_addr_t)raw_profile_data,
        .profile_data_len = raw_profile_len,
        .container_root_path = (user_addr_t)container_root_path,
        .container_root_path_len = strlen(container_root_path) + 1,
        .unknown = 0
    };

    if (__sandbox_ms("Sandbox", 0, &params)) {
        FATAL_FORMAT("SYSCALL_SET_PROFILE", "Could not set sandbox profile data: %s (%d)",
            strerror(errno), errno);
    }

    chdir(container_root_path);
    setenv("HOME", container_root_path, 1);
    setenv("CFFIXED_USER_HOME", container_root_path, 1);
    unsetenv("TMPDIR");
    setenv("APP_SANDBOX_CONTAINER_ID", container_id, 1);

    uint64_t qtn_flag_set = xpc_dictionary_get_uint64(response,
        "SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY");

    /*
     * Not properly understood for now.
     * ???
     */
    if (qtn_flag_set) {
        user_addr_t params[] = {
            *(user_addr_t*)_NSGetProgname(),
            0, 0, 0, 0,
            qtn_flag_set
        };

        __sandbox_ms("Quarantine", 87, params);
    }

    errno = 0;

    /*
     * According to man(3) confstr:
     *      If len is non-zero, buf is a non-null pointer, and name has a
     *      value, up to len - 1 bytes of the value are copied into the buffer buf.
     *      The copied value is always null terminated.
     * This would suggest that the code below is illegal. However, confstr appears to
     * nevertheless do the right thing and does not crash.
     *
     * Possible reason for calling this function: It creates the temporary directory,
     * if it does not exist already.
     */
    confstr(_CS_DARWIN_USER_TEMP_DIR, NULL, 0x400);

    if (ctx->flags.exit_after_init)
        exit(0);
}

#if defined(MAC_OS_MOJAVE)
static int _libsecinit_fileoperation_request_send(xpc_object_t request, xpc_object_t* response)
{
    *response = NULL;
    xpc_pipe_t pipe = xpc_pipe_create("com.apple.secinitd.fileoperations", 0);
    if (!pipe) {
        DEBUG_FORMAT("Failed to connect to com.apple.secinitd.fileoperations");
        return 1;
    }

    int rc = xpc_pipe_routine(pipe, request, response);
    xpc_release(pipe);

    if (rc) {
        DEBUG_FORMAT("libsecinit: send request: xpc_pipe_routine() failed with code %d\n",
            rc);
        return 5; /* 5 and 1 (see above) are returned by this function on error */
    }

    return 0;
}

#define LIBSECINIT_FILEOPERATIONS_INVALID_ARGS 0x16
#define LIBSECINIT_FILEOPERATIONS_OOM 0xc

int libsecinit_fileoperation_symlink(
    uint8_t* authorization,
    const char* source,
    const char* target,
    xpc_object_t* err)
{
    if (err) {
        *err = NULL;
    }

    if (!authorization || !source || strlen(source) == 0 || strlen(source) >= 1024 || !target || strlen(target) >= 1024) {
        return LIBSECINIT_FILEOPERATIONS_INVALID_ARGS;
    }

    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    if (!dict) {
        return LIBSECINIT_FILEOPERATIONS_OOM;
    }

    xpc_dictionary_set_uint64(dict,
        "SECINITD_MESSAGE_TYPE_KEY", 1);
    xpc_dictionary_set_data(dict,
        "FILEOP_REQUEST_AUTHORIZATION", authorization, 32);
    xpc_dictionary_set_string(dict,
        "FILEOP_REQUEST_SOURCE", source);
    xpc_dictionary_set_string(dict,
        "FILEOP_REQUEST_TARGET", target);

    xpc_object_t response = NULL;
    int rc = _libsecinit_fileoperation_request_send(dict, &response);

    if (response) {
        rc = xpc_dictionary_get_int64(response, "FILEOP_REPLY_OSSTATUS");
        if (rc != 0) {
            size_t data_len = 0;
            const void* data = xpc_dictionary_get_data(response, "FILEOP_REPLY_ERROR", &data_len);
            if (data && data_len > 0) {
                *err = xpc_data_create(data, data_len);
            }
        }
        xpc_release(response);
    }

    xpc_release(dict);

    return rc;
}

int libsecinit_fileoperation_save(
    uint8_t* authorization,
    const char* source,
    const char* target,
    xpc_object_t* err)
{
    if (err) {
        *err = NULL;
    }

    if (!authorization || !source || strlen(source) == 0 || strlen(source) >= 1024 || !target || strlen(target) >= 1024) {
        return LIBSECINIT_FILEOPERATIONS_INVALID_ARGS;
    }

    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    if (!dict) {
        return LIBSECINIT_FILEOPERATIONS_OOM;
    }

    xpc_dictionary_set_uint64(dict,
        "SECINITD_MESSAGE_TYPE_KEY", 2);
    xpc_dictionary_set_data(dict,
        "FILEOP_REQUEST_AUTHORIZATION", authorization, 32);
    xpc_dictionary_set_string(dict,
        "FILEOP_REQUEST_SOURCE", source);
    xpc_dictionary_set_string(dict,
        "FILEOP_REQUEST_TARGET", target);

    xpc_object_t response = NULL;
    int rc = _libsecinit_fileoperation_request_send(dict, &response);

    if (response) {
        rc = xpc_dictionary_get_int64(response, "FILEOP_REPLY_OSSTATUS");
        if (rc != 0) {
            size_t data_len = 0;
            const void* data = xpc_dictionary_get_data(response, "FILEOP_REPLY_ERROR", &data_len);
            if (data && data_len > 0) {
                *err = xpc_data_create(data, data_len);
            }
        }
        xpc_release(response);
    }

    xpc_release(dict);

    return rc;
}

int libsecinit_fileoperation_set_attributes(
    uint8_t* authorization,
    const char* target,
    xpc_object_t attributes,
    xpc_object_t* err)
{
    if (err) {
        *err = NULL;
    }

    if (!authorization || !target || strlen(target) >= 1024) {
        return LIBSECINIT_FILEOPERATIONS_INVALID_ARGS;
    }

    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    if (!dict) {
        return LIBSECINIT_FILEOPERATIONS_OOM;
    }

    xpc_dictionary_set_uint64(dict,
        "SECINITD_MESSAGE_TYPE_KEY", 3);
    xpc_dictionary_set_data(dict,
        "FILEOP_REQUEST_AUTHORIZATION", authorization, 32);
    xpc_dictionary_set_string(dict,
        "FILEOP_REQUEST_TARGET", target);
    xpc_dictionary_set_value(dict,
        "FILEOP_REQUEST_ATTRIBUTES", attributes);

    xpc_object_t response = NULL;
    int rc = _libsecinit_fileoperation_request_send(dict, &response);

    if (response) {
        rc = xpc_dictionary_get_int64(response, "FILEOP_REPLY_OSSTATUS");
        if (rc != 0) {
            size_t data_len = 0;
            const void* data = xpc_dictionary_get_data(response, "FILEOP_REPLY_ERROR", &data_len);
            if (data && data_len > 0) {
                *err = xpc_data_create(data, data_len);
            }
        }
        xpc_release(response);
    }

    xpc_release(dict);

    return rc;
}
#endif
