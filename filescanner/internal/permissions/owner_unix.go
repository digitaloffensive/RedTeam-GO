//go:build !windows

package permissions

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
)

func getOwner(info os.FileInfo) string {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown"
	}
	u, err := user.LookupId(fmt.Sprintf("%d", sys.Uid))
	if err != nil {
		return fmt.Sprintf("uid:%d", sys.Uid)
	}
	return u.Username
}
