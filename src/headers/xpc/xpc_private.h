/*
 * This header file is contrived of declarations for Apple-internal functions,
 * structure definitions and typedefs needed to call specific functions
 * that lack a public interface. Wherever possible, references to the original
 * header file are given. If such a reference is lacking, the declaration was
 * created by manual reverse engineering.
 *
 * It was not possible to link to the original headers, as these cannot contain
 * references to headers that have not been released publicly.
 */
#ifndef _HEADER_XPC_PRIVATE
#define _HEADER_XPC_PRIVATE

#include <xpc/xpc.h>

/*
 * Referenced all over the place, e.g. here:
 * https://opensource.apple.com/source/launchd/launchd-842.1.4/src/core.c
 * The following declaration follows.
 */
extern xpc_object_t xpc_copy_entitlements_for_pid(pid_t pid);

/*
 * Taken from 
 * https://github.com/samdmarshall/OSXPrivateSDK
 */
extern xpc_object_t xpc_create_from_plist(const void *data, size_t len);

/*
 * This is likely not the correct definition for xpc_pipe_t.
 *
 * However, we don't need to know exactly what such an object is, we can treat
 * it as a blackbox. As such, void * suffices.
 */
typedef void *xpc_pipe_t;

/*
 * Found in https://github.com/apportable/lookup/blob/master/ds_module.c
 */
extern xpc_pipe_t xpc_pipe_create(const char *name, uint64_t flags);
extern int xpc_pipe_routine(xpc_pipe_t pipe, xpc_object_t message, xpc_object_t *reply);

#endif // _HEADER_XPC_PRIVATE