#ifndef _LIBSECINIT_H
#define _LIBSECINIT_H

/**
 * Initialize the App Sandbox
 */
void _libsecinit_initializer();

/**
 * Functions added with macOS Mojave 10.14.
 * Not present in earlier versions of the OS.
 */
#if defined(MAC_OS_MOJAVE)
int libsecinit_fileoperation_symlink(
    uint8_t* authorization,
    const char* source,
    const char* target,
    xpc_object_t* err);

int libsecinit_fileoperation_save(
    uint8_t* authorization,
    const char* source,
    const char* target,
    xpc_object_t* err;);

int libsecinit_fileoperation_set_attributes(
    uint8_t* authorization,
    const char* target,
    xpc_object_t attributes,
    xpc_object_t* err);
#endif

#endif // _LIBSECINIT_H