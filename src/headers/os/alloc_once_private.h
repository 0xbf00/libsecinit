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
#ifndef _HEADER_ALLOC_ONCE
#define _HEADER_ALLOC_ONCE

/* 
 * Keys for use with os_once_alloc.
 *
 * Taken from <os/alloc_once_private.h>, part of Apple's libsystem package.
 * Download the package on opensource.apple.com
 */
#define OS_ALLOC_ONCE_KEY_LIBSECINIT				18

/*
 * Necessary typedef for the following code
 * Taken from libplatform's <os/once_private.h>
 */
typedef long os_once_t;

/*
 * Necessary typedef for the following code
 * Taken from libplatform's <os/base.h>
 */
typedef void (*os_function_t)(void *);

/*
 * os_alloc_once() related declarations and function definition.
 *
 * Taken from <os/alloc_once_impl.h>, as released as part of the libplatform
 * package.
 */
typedef os_once_t os_alloc_token_t;
struct _os_alloc_once_s {
	os_alloc_token_t once;
	void *ptr;
};

__OSX_AVAILABLE_STARTING(__MAC_10_9,__IPHONE_6_0)
extern struct _os_alloc_once_s _os_alloc_once_table[];

__OSX_AVAILABLE_STARTING(__MAC_10_9,__IPHONE_6_0)
OS_EXPORT OS_NONNULL1
void*
_os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);

/* 
 * The region allocated by os_alloc_once is 0-filled when initially
 * returned (or handed off to the initializer).
 */
// OS_WARN_RESULT OS_NOTHROW OS_CONST
__header_always_inline void*
os_alloc_once(os_alloc_token_t token, size_t sz, os_function_t init)
{
	struct _os_alloc_once_s *slot = &_os_alloc_once_table[token];
	if (OS_EXPECT(slot->once, ~0l) != ~0l) {
		void *ptr = _os_alloc_once(slot, sz, init);
		OS_COMPILER_CAN_ASSUME(slot->once == ~0l);
		return ptr;
	}
	return slot->ptr;
}

#endif // _HEADER_ALLOC_ONCE