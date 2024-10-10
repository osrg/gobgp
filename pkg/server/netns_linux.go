// Copyright (C) 2022 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package server

import (
	stderrors "errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	DefaultNetns = "##defaultNetns##"
	UnnamedNetns = "##unnamedNetns##"
)

func getNsRunDir() string {
	xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")

	/// If XDG_RUNTIME_DIR is set, check if the current user owns /var/run.  If
	// the owner is different, we are most likely running in a user namespace.
	// In that case use $XDG_RUNTIME_DIR/netns as runtime dir.
	if xdgRuntimeDir != "" {
		if s, err := os.Stat("/var/run"); err == nil {
			st, ok := s.Sys().(*syscall.Stat_t)
			if ok && int(st.Uid) != os.Geteuid() {
				return path.Join(xdgRuntimeDir, "netns")
			}
		}
	}

	return "/var/run/netns"
}

// GetCurrentThreadNetNSPath copied from containernetworking/plugins/pkg/ns
func GetCurrentThreadNetNSPath() string {
	// /proc/self/ns/net returns the namespace of the main thread, not
	// of whatever thread this goroutine is running on.  Make sure we
	// use the thread's net namespace since the thread is switching around
	return fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
}

/**
 * This function was forked from the following repo [0]
 * as we depend on pkg/ns, but it doesnot support netns creation
 * [0] https://github.com/containernetworking/plugins/blob/main/pkg/testutils/netns_linux.go
 */
func MountNs(ns netns.NsHandle, nsName string) error {
	// Creates a new persistent (bind-mounted) network namespace and returns an object
	// representing that namespace, without switching to it.

	nsRunDir := getNsRunDir()

	// Create the directory for mounting network namespaces
	// This needs to be a shared mountpoint in case it is mounted in to
	// other namespaces (containers)
	err := os.MkdirAll(nsRunDir, 0755)
	if err != nil {
		return err
	}

	// Remount the namespace directory shared. This will fail if it is not
	// already a mountpoint, so bind-mount it on to itself to "upgrade" it
	// to a mountpoint.
	err = unix.Mount("", nsRunDir, "none", unix.MS_SHARED|unix.MS_REC, "")
	if err != nil {
		if err != unix.EINVAL {
			return fmt.Errorf("mount --make-rshared %s failed: %q", nsRunDir, err)
		}

		// Recursively remount /var/run/netns on itself. The recursive flag is
		// so that any existing netns bindmounts are carried over.
		err = unix.Mount(nsRunDir, nsRunDir, "none", unix.MS_BIND|unix.MS_REC, "")
		if err != nil {
			return fmt.Errorf("mount --rbind %s %s failed: %q", nsRunDir, nsRunDir, err)
		}

		// Now we can make it shared
		err = unix.Mount("", nsRunDir, "none", unix.MS_SHARED|unix.MS_REC, "")
		if err != nil {
			return fmt.Errorf("mount --make-rshared %s failed: %q", nsRunDir, err)
		}

	}

	// create an empty file at the mount point
	nsPath := path.Join(nsRunDir, nsName)
	mountPointFd, err := os.Create(nsPath)
	if err != nil {
		return err
	}
	mountPointFd.Close()

	// Ensure the mount point is cleaned up on errors; if the namespace
	// was successfully mounted this will have no effect because the file
	// is in-use
	defer os.RemoveAll(nsPath)

	// bind mount the netns from the current thread (from /proc) onto the
	// mount point. This causes the namespace to persist, even when there
	// are no threads in the ns.
	err = unix.Mount(GetCurrentThreadNetNSPath(), nsPath, "none", unix.MS_BIND, "")
	if err != nil {
		err = fmt.Errorf("failed to bind mount ns at %s: %v", nsPath, err)
	}

	if err != nil {
		return fmt.Errorf("failed to create namespace: %v", err)
	}

	return nil
}

func NetNsExec(netnsName string, cb func() error) (err error) {
	netnsCleanup, err := NsEnter(netnsName)
	defer netnsCleanup()
	if err != nil {
		return err
	}
	return cb()
}

// NsEnter switches the goroutine to the given netnsName
// and provides the cleanup function
func NsEnter(netnsName string) (cleanup func(), err error) {
	stack := make([]func(), 0)
	cleanup = func() {
		for i := len(stack) - 1; i >= 0; i-- {
			stack[i]()
		}
	}
	if netnsName == "" || netnsName == DefaultNetns {
		return cleanup, nil
	}
	runtime.LockOSThread()
	stack = append(stack, runtime.UnlockOSThread)

	origns, _ := netns.Get()
	stack = append(stack, func() {
		err := origns.Close()
		if err != nil {
			fmt.Printf("Cannot close initial netns fd %s", err)
		}
	})

	var targetns netns.NsHandle
	if netnsName == UnnamedNetns {
		// We call netns.New() below
	} else if strings.HasPrefix(netnsName, "pid:") {
		pid, err := strconv.ParseInt((netnsName)[4:], 10, 64)
		if err != nil {
			return cleanup, err
		}
		targetns, err = netns.GetFromPid(int(pid))
		if err != nil {
			return cleanup, fmt.Errorf("Cannot get %s netns from pid: %v", err)
		}
	} else {
		targetns, err = netns.GetFromName(netnsName)
		if err != nil {
			return cleanup, fmt.Errorf("Cannot get %s netns: %v", netnsName, err)
		}
	}

	stack = append(stack, func() {
		err := targetns.Close()
		if err != nil {
			fmt.Printf("Cannot close target netns fd %s", err)
		}
	})

	if netnsName == UnnamedNetns {
		targetns, err = netns.New()
		if err != nil {
			return cleanup, fmt.Errorf("Cannot create new netns: %v", err)
		}
	} else {
		err = netns.Set(targetns)
		if err != nil {
			return cleanup, fmt.Errorf("Cannot nsenter %s: %v", netnsName, err)
		}
	}
	stack = append(stack, func() {
		if err := netns.Set(origns); err != nil {
			fmt.Printf("Cannot nsenter initial netns %s", err)
		}
	})
	return cleanup, nil
}

func EnsureNetnsExists(netnsName string) (err error) {
	if netnsName == "" || strings.HasPrefix(netnsName, "pid:") {
		return nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()

	ns, err := netns.GetFromName(netnsName)
	if err != nil {
		if stderrors.Is(os.ErrNotExist, err) {
			ns, err := netns.New()
			if err != nil {
				return fmt.Errorf("Could not create netns for %s: %v", netnsName, err)
			}
			defer ns.Close()
			err = MountNs(ns, netnsName)
			if err != nil {
				return fmt.Errorf("Could not mount netns to %s: %v", netnsName, err)
			}
		} else {
			return fmt.Errorf("Cannot get %s netns: %v", netnsName, err)
		}
	} else {
		ns.Close()
	}

	return netns.Set(origns)
}
