/**
 * Definitions for various helper macros.
 */
#ifndef _MISC_H
#define _MISC_H

#include <stdio.h>

#if defined(DEBUG) || defined(TRACE)
#define DEBUG_FORMAT(format, ...)               \
    do {                                        \
        fprintf(stderr, format, ##__VA_ARGS__); \
    } while (0);
#else
#define DEBUG_FORMAT(format, ...)
#endif

#define FATAL_MSG(msg)             \
    do {                           \
        DEBUG_FORMAT("%s\n", msg); \
        __builtin_trap();          \
    } while (0);
#define FATAL_FORMAT(action, format, ...)                  \
    do {                                                   \
        char buf[2048];                                    \
        snprintf(buf, sizeof(buf), format, ##__VA_ARGS__); \
        DEBUG_FORMAT("[%s]: %s\n", action, buf);           \
        __builtin_trap();                                  \
    } while (0);

#define XPC_TRACE(str, obj)                       \
    do {                                          \
        char* desc = xpc_copy_description((obj)); \
        DEBUG_FORMAT("%s: %s\n", (str), (desc));  \
        free(desc);                               \
    } while (0);

/**
 * Number of elements in array. Works only for
 * arrays declared and defined statically in code.
 *
 * Thankfully, should throw compiler errors if you
 * try to use it in other ways.
 */
#define ARR_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

#endif // _MISC_H