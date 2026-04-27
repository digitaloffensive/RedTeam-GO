//go:build windows

package permissions

// canRead on Windows uses CreateFile with GENERIC_READ and full share flags.
// This correctly handles UNC paths (\\server\share\file) and avoids the
// false negatives that os.Open can produce on locked network share files.
func canRead(path string) bool {
	return canReadWindows(path)
}

// canWrite on Windows uses CreateFile with GENERIC_WRITE and OPEN_EXISTING.
// This is more reliable than os.OpenFile(O_WRONLY|O_APPEND) on Windows because:
//   - It correctly handles UNC/network share paths
//   - It uses FILE_SHARE_READ|WRITE|DELETE to avoid sharing violations on
//     files that are open by other processes but are still writable by us
//   - It does NOT modify or truncate the file (OPEN_EXISTING, no O_TRUNC)
func canWrite(path string) bool {
	return canWriteWindows(path)
}
