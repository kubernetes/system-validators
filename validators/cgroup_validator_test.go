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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCgroupSubsystem(t *testing.T) {
	// hardcoded cgroup v2 subsystems
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
