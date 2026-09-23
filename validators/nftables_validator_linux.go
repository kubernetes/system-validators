//go:build linux
// +build linux

/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package system

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Netfilter / nftables constants not explicitly exported in the syscall or unix package
const (
	// https://github.com/torvalds/linux/blob/1d5dcaa3bd65f2e8c9baa14a393d3a2dc5db7524/include/uapi/linux/netfilter/nfnetlink.h#L61
	nfnlSubsysNftables = 10
	// https://github.com/torvalds/linux/blob/1d5dcaa3bd65f2e8c9baa14a393d3a2dc5db7524/include/uapi/linux/netfilter/nf_tables.h#L116
	nftMsgGettable = 1
)

// nfgenmsg is the Netfilter Generic Message header (4 bytes)
// https://github.com/torvalds/linux/blob/1d5dcaa3bd65f2e8c9baa14a393d3a2dc5db7524/include/uapi/linux/netfilter/nfnetlink.h#L32-L38
type nfgenmsg struct {
	nfgenFamily uint8
	version     uint8
	resID       uint16
}

// used for test injection
var sysfsModuleDir = "/sys/module/nf_tables"

var _ Validator = &nftablesValidator{}

// nftablesValidator validates that nftables is enabled on Linux.
type nftablesValidator struct {
	reporter      Reporter
	nftablesCheck func() (bool, error) // used for test injection
}

// Name is part of the system.Validator interface.
func (n *nftablesValidator) Name() string {
	return "nftables"
}

// Validate is part of the system.Validator interface.
func (n *nftablesValidator) Validate(spec SysSpec) ([]error, []error) {
	if !spec.Nftables {
		return nil, nil
	}

	// Check sysfs first (requires zero privileges).
	if _, err := os.Stat(sysfsModuleDir); err == nil {
		n.reporter.Report("NFTABLES", "enabled", good)
		return nil, nil
	}

	//If the nftables module isn't loaded, run the netlink query.
	check := n.nftablesCheck
	if check == nil {
		check = isNftablesEnabledNetlink
	}

	enabled, err := check()
	if err != nil {
		// Raw netlink sockets require CAP_NET_ADMIN (root).
		// If running as non-root, report a warning instead of a validation error.
		if errors.Is(err, os.ErrPermission) ||
			errors.Is(err, syscall.EACCES) ||
			errors.Is(err, syscall.EPERM) {
			n.reporter.Report("NFTABLES", "unknown (requires root)", warn)
			return []error{fmt.Errorf("unable to check nftables status: %w", err)}, nil
		}
		n.reporter.Report("NFTABLES", "error", bad)
		return nil, []error{fmt.Errorf("failed to validate nftables: %w", err)}
	}

	if enabled {
		n.reporter.Report("NFTABLES", "enabled", good)
		return nil, nil
	}

	n.reporter.Report("NFTABLES", "disabled", bad)
	return nil, []error{errors.New("nftables is disabled")}
}

func isNftablesEnabledNetlink() (bool, error) {
	// Open a Netlink socket targeting the Netfilter subsystem.
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return false, fmt.Errorf("failed to open netlink socket: %w", err)
	}
	defer syscall.Close(fd)

	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, lsa); err != nil {
		return false, fmt.Errorf("failed to bind socket: %w", err)
	}

	// Construct the Netlink Message
	// Total length = Size of Netlink Header (16 bytes) + Size of Netfilter Header (4 bytes) = 20 bytes
	buf := new(bytes.Buffer)

	// nft list tables
	hdr := syscall.NlMsghdr{
		Len:   20,
		Type:  (nfnlSubsysNftables << 8) | nftMsgGettable,
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_DUMP, // Request a dump of all tables
		Seq:   1,
		Pid:   0,
	}

	// nfgenmsg: Netfilter generic message header (4 bytes)
	nfgen := nfgenmsg{
		nfgenFamily: syscall.AF_UNSPEC, // Check all protocol families
		version:     0,                 // NFNETLINK_V0
		resID:       0,
	}

	// Netlink and Netfilter headers must be serialized using the host's native byte order
	if err := binary.Write(buf, binary.NativeEndian, hdr); err != nil {
		return false, err
	}
	if err := binary.Write(buf, binary.NativeEndian, nfgen); err != nil {
		return false, err
	}

	// Send the packet to the kernel
	err = syscall.Sendto(fd, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		return false, fmt.Errorf("failed to send netlink message: %w", err)
	}

	// Read the kernel's response
	rb := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, rb, 0)
	if err != nil {
		return false, fmt.Errorf("failed to receive netlink message: %w", err)
	}

	// Parse the returning Netlink messages
	msgs, err := syscall.ParseNetlinkMessage(rb[:n])
	if err != nil {
		return false, fmt.Errorf("failed to parse netlink response: %w", err)
	}

	if len(msgs) == 0 {
		return false, fmt.Errorf("received empty netlink response")
	}

	respHdr := msgs[0].Header

	// Evaluate the kernel's answer
	if respHdr.Type == syscall.NLMSG_ERROR {
		if len(msgs[0].Data) < 4 {
			return false, fmt.Errorf("received malformed netlink error payload")
		}

		// The error code is a negative int32 right after the header
		var errCode int32
		binary.Read(bytes.NewReader(msgs[0].Data[:4]), binary.NativeEndian, &errCode)

		if errCode == 0 {
			return true, nil
		}

		// Convert negative error code to a standard Go/Linux errno
		errno := syscall.Errno(-errCode)
		// missing or disabled
		if errno == syscall.EOPNOTSUPP || errno == syscall.EPROTONOSUPPORT || errno == syscall.ENOENT {
			return false, nil
		}

		return false, fmt.Errorf("unexpected netlink error: %w", errno)
	}

	return true, nil
}
