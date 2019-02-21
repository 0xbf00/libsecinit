## Libsecinit

This repository contains code that faithfully reimplements (apart from error handling) the logic in Apple's `libsystem_secinit.dylib` responsible for kickstarting the App Sandbox on macOS.

This project complements analysis done by Jonathan Levin and others that have looked at sandbox initialisation on macOS. In particular, other works often sniff XPC messages to analyse the simple protocol between `libsystem_secinit.dylib` and `secinitd`. A full reimplementation as presented here can be used to experiment with this system on another level and might be useful to bug hunters to speed up their analysis of the system.

Note: Rebuilding source code for software from just a binary is tedious work. This is a best-efforts attempt -- in the end, there is no guarantee the code is correct (by which I mean logically _identical to Apple's_).

## Building

To build, simply invoke

```sh
cd src
# For Mojave compatible library
make mojave
# For High Sierra compatible library
make high_sierra
# For Sierra compatible library
make sierra
```

By default, the `make` command builds the library for macOS Mojave (10.14).

## Using

Because Apple's libraries are protected both by **SIP** and by **Library Validation**, simply replacing the original library at `/usr/lib/system/` will not work. You probably need Kernel patches to install this library system wide. Still, you can use it on individual, sandboxed programs and apps as follows (though you might need to *disable* SIP):

```sh
$ DYLD_INSERT_LIBRARIES=libsystem_secinit.dylib /Applications/Calculator.app/Contents/MacOS/Calculator
sandbox request: <dictionary: 0x7fb0cb400770> { count = 11, transaction: 0, voucher = 0x0, contents =
	"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY" => <string: 0x7fb0cb50d630> { length = 10, contents = "Calculator" }
	"SECINITD_REGISTRATION_MESSAGE_IS_SANDBOX_CANDIDATE_KEY" => <bool: 0x7fff8d0bfbe8>: true
	"SECINITD_REGISTRATION_MESSAGE_APPIOSMAC" => <bool: 0x7fff8d0bfc08>: false
	"SECINITD_REGISTRATION_MESSAGE_ENTITLEMENTS_DICT_KEY" => <dictionary: 0x7fb0cb4005c0> { count = 4, transaction: 0, voucher = 0x0, contents =
		"com.apple.security.app-sandbox" => <bool: 0x7fff8d0bfbe8>: true
		"com.apple.security.print" => <bool: 0x7fff8d0bfbe8>: true
		"com.apple.security.files.user-selected.read-write" => <bool: 0x7fff8d0bfbe8>: true
		"com.apple.security.network.client" => <bool: 0x7fff8d0bfbe8>: true
	}
	"SECINITD_REGISTRATION_MESSAGE_IMAGES_IN_SHARED_CACHE_KEY" => <array: 0x7fb0cb400890> { count = 257, capacity = 512, contents =
		0: <bool: 0x7fff8d0bfc08>: false
		.
		.
		.
		256: <bool: 0x7fff8d0bfbe8>: true
	}
	"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY" => <array: 0x7fb0cb400a30> { count = 257, capacity = 512, contents =
		0: <string: 0x7fb0cb400940> { length = 54, contents = "/Applications/Calculator.app/Contents/MacOS/Calculator" }
		.
		.
		.
		256: <string: 0x7fb0cb50d320> { length = 72, contents = "/System/Library/PrivateFrameworks/AppleSRP.framework/Versions/A/AppleSRP" }
	}
	"SECINITD_REGISTRATION_MESSAGE_VERSION_NUMBER_KEY" => <uint64: 0xce92eea7963fe775>: 1
	"SECINITD_REGISTRATION_MESSAGE_APPSANDBOX_EXIT_AFTER_INIT" => <bool: 0x7fff8d0bfc08>: false
	"SECINITD_REGISTRATION_MESSAGE_DYLD_VARIABLES_KEY" => <dictionary: 0x7fb0cb50d420> { count = 1, transaction: 0, voucher = 0x0, contents =
		"DYLD_INSERT_LIBRARIES" => <string: 0x7fb0cb50d500> { length = 23, contents = "libsystem_secinit.dylib" }
	}
	"SECINITD_REGISTRATION_MESSAGE_UUID" => <uuid: 0x7fb0cb6001d0> 3D3E272B-6E33-4625-B40A-86C28C41459E
	"SECINITD_MESSAGE_TYPE_KEY" => <uint64: 0xce92eea7963fe775>: 1
}
sandbox response: <dictionary: 0x7fb0cb400b80> { count = 7, transaction: 0, voucher = 0x0, contents =
	"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY" => <string: 0x7fb0cb4008c0> { length = 20, contents = "com.apple.calculator" }
	"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY" => <uint64: 0xce92eea7963fd775>: 2
	"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY" => <string: 0x7fb0cb401050> { length = 57, contents = "/Users/jakob/Library/Containers/com.apple.calculator/Data" }
	"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY" => <data: 0x7fb0cb401120>: { length = 22706 bytes, contents = 0x0000e800f400f4002e000000e700e500e400e700e700e700... }
	"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY" => <int64: 0x7fb0cb401030>: 1
	"SECINITD_MESSAGE_TYPE_KEY" => <uint64: 0xce92eea7963fd775>: 2
	"SECINITD_REPLY_FAILURE_CODE" => <uint64: 0xce92eea7963ff775>: 0
}
```

If you specify the **TRACE** or **DEBUG** C defines while building, you'll see the XPC dictionaries used to communicate with `secinitd`. Because these defines are included in the default Makefile, they are included in the example output above.