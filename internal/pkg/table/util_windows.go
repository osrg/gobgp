//go:build windows

package table

// #include <windows.h>
import "C"

func SystemMemoryAvailableMiB() uint64 {
	MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return uint64(status.ullAvailPhys) / (1024 * 1024)
}
