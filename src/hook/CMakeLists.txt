
file(GLOB HEADER_FILES
	"DebugStackTracer.h"
	"HookingEngine.h"
	"Logger.h"
	"Memory.h"
	"SharedMemoryArray.h"
	"StackWalker.h"
	"SyncLock.cpp"
	"SyncLock.h"
	"TrackedMemoryBlock.h"
	"UnpackingEngine.h"
	"ntdefs.h"
)
file(GLOB SOURCE_FILES
    "Logger.cpp"
	"dllmain.cpp"
	"UnpackingEngine.cpp"
	"StackWalker.cpp"
	"UnpackingEngine.cpp"
)


add_library(PackerAttackerHook SHARED
	${SOURCE_FILES}
	${HEADER_FILES}
)

source_group("Headers"                          FILES ${HEADER_FILES})
source_group("Sources"                          FILES ${SOURCE_FILES})