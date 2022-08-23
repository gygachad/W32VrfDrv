#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntintsafe.h>
#include <windef.h>
#include <ntimage.h>
#include <fltKernel.h>

#include "Debug.h"

#include "HookTools\AsmTool.h"
#include "HookTools\Win_Tools.h"
#include "HookTools\ImportHook.h"

#include "MemoryHooks\MemoryLog.h"
#include "MemoryHooks\RtlHeapHook.h"

#include "RtlHeapVerifier.h"
#include "W32VrfDrv.h"