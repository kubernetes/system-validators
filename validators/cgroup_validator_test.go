//go:build linux
// +build linux

/*
Copyright 2016 The Kubernetes Authors.

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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCgroupSubsystem(t *testing.T) {
	// hardcoded cgroups v2 subsystems
	pseudoSubsystems := []string{"devices", "freezer"}

	v := &CgroupsValidator{
		Reporter: DefaultReporter,
	}
	for desc, test := range map[string]struct {
		subsystems []string
		cgroupSpec []string
		required   bool
		missing    []string
	}{
		"missing required cgroup subsystem should report missing": {
			cgroupSpec: []string{"system1", "system2"},
			subsystems: []string{"system1"},
			required:   true,
			missing:    []string{"system2"},
		},
		"missing optional cgroup subsystem should report missing": {
			cgroupSpec: []string{"system1", "system2"},
			subsystems: []string{"system1"},
			required:   false,
			missing:    []string{"system2"},
		},
		"extra cgroup subsystems should not report missing": {
			cgroupSpec: []string{"system1", "system2"},
			subsystems: []string{"system1", "system2", "system3"},
			required:   true,
			missing:    nil,
		},
		"subsystems the same with spec should not report missing": {
			cgroupSpec: []string{"system1"},
			subsystems: []string{"system1", "system2"},
			required:   false,
			missing:    nil,
		},
		"missing required cgroup subsystem when pseudo hardcoded subsystems are set": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: pseudoSubsystems,
			required:   true,
			missing:    []string{"system1"},
		},
		"missing optional cgroup subsystem when pseudo hardcoded subsystems are set": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: pseudoSubsystems,
			required:   false,
			missing:    []string{"system1"},
		},
		"extra cgroup subsystems when pseudo hardcoded subsystems are set": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: append(pseudoSubsystems, "system1", "system2"),
			required:   true,
			missing:    nil,
		},
		"matching list of cgroup subsystems including pseudo hardcoded subsystems": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: append(pseudoSubsystems, "system1"),
			required:   false,
			missing:    nil,
		},
	} {
		t.Run(desc, func(t *testing.T) {
			missing := v.validateCgroupSubsystems(test.cgroupSpec, test.subsystems, test.required)
			assert.Equal(t, test.missing, missing, "%q: Expect error not to occur with cgroup", desc)
		})
	}
}

func TestGetUnifiedMountpoint(t *testing.T) {
	c, err := os.Open(filepath.Join(defaultUnifiedMountPoint, "cgroup.controllers"))
	if err == nil {
		defer c.Close()
	}
	tests := map[string]struct {
		mountsFileContent   string
		expectedErr         bool
		expectedPath        string
		expectedIsCgroupsV2 bool
		// when /sys/fs/cgroup is mounted as tmpfs,
		// the cgroup version check depends on checking local dir: `/sys/fs/cgroup/memory`
		skipIsCgroupsV2Check bool
	}{
		"cgroups v2": {
			mountsFileContent:   "cgroup2 /sys/fs/cgroup cgroup2 rw,seclabel,nosuid,nodev,noexec,relatime 0 0",
			expectedErr:         false,
			expectedPath:        "/sys/fs/cgroup",
			expectedIsCgroupsV2: true,
		},
		"cgroups v1": {
			mountsFileContent: "cgroup /sys/fs/cgroup cgroup rw,seclabel,nosuid,nodev,noexec,relatime 0 0",
			expectedErr:       false,
			expectedPath:      "/sys/fs/cgroup",
		},
		"empty file": {
			mountsFileContent: "",
			expectedErr:       true,
			expectedPath:      "",
		},
		"no cgroup mounts": {
			mountsFileContent: `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0`,
			expectedErr:  true,
			expectedPath: "",
		},
		"multiple cgroups v1 and v2": {
			mountsFileContent: `cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,seclabel,nosuid,nodev,noexec,relatime`,
			expectedErr:         false,
			expectedPath:        "/sys/fs/cgroup/unified",
			expectedIsCgroupsV2: true,
		},
		"cgroups v1 only with multiple subsystems": {
			mountsFileContent: `cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory`,
			expectedErr:  false,
			expectedPath: "/sys/fs/cgroup/cpuset", // First valid cgroups v1 path
		},
		"no valid cgroup": {
			mountsFileContent: "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0",
			expectedErr:       true,
			expectedPath:      "",
		},
		"cgroups using tmpfs, v1 and v2": {
			mountsFileContent: `tmpfs /run tmpfs rw,nosuid,nodev,size=803108k,nr_inodes=819200,mode=755 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,size=4096k,nr_inodes=1024,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0`,
			expectedErr:          false,
			expectedPath:         "/sys/fs/cgroup",
			skipIsCgroupsV2Check: true,
		},
		"cgroups using tmpfs, v1": {
			mountsFileContent: `tmpfs /sys/fs/cgroup tmpfs ro,seclabel,nosuid,nodev,noexec,mode=755 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,seclabel,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,seclabel,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,seclabel,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,seclabel,nosuid,nodev,noexec,relatime,memory 0 0`,
			expectedErr:          false,
			expectedPath:         "/sys/fs/cgroup",
			skipIsCgroupsV2Check: true,
		},
	}

	for desc, test := range tests {
		t.Run(desc, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "mounts")
			assert.NoError(t, err, "Unexpected error creating temp file")
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.Write([]byte(test.mountsFileContent))
			assert.NoError(t, err, "Unexpected error writing to temp file")
			tmpFile.Close()

			path, isCgroupsV2, err := getUnifiedMountpoint(tmpFile.Name())

			if test.expectedErr {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Did not expect error but got one: %s", err)
			}

			assert.Equal(t, test.expectedPath, path, "Expected cgroup path mismatch")
			if !test.skipIsCgroupsV2Check {
				assert.Equal(t, test.expectedIsCgroupsV2, isCgroupsV2, "Expected cgroup version mismatch")
			}
		})
	}
}

func TestIsCgroupsV1DisabledInKubelet(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		expectedResult bool
		expectedError  bool
	}{
		{
			name:          "invalid version",
			version:       "foo",
			expectedError: true,
		},
		{
			name:           "empty version",
			version:        "",
			expectedResult: false,
		},
		{
			name:           "version older than 1.35.0-0 causes a warning",
			version:        "1.34.7",
			expectedResult: false,
		},
		{
			name:           "1.35.0 pre-release causes an error",
			version:        "1.35.0-alpha.1",
			expectedResult: true,
		},
		{
			name:           "newer versions than 1.35 cause an error",
			version:        "1.35.1",
			expectedResult: true,
		},
	}

	v := CgroupsValidator{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v.KubeletVersion = tc.version
			result, err := v.isCgroupsV1DisabledInKubelet()

			if (err != nil) != tc.expectedError {
				t.Fatalf("expected error: %v, got: %v", tc.expectedError, err != nil)
			}
			if result != tc.expectedResult {
				t.Fatalf("expected result: %v, got: %v", tc.expectedResult, result)
			}
		})
	}
}
