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
	"errors"
	"testing"
)

type fakeValidator struct {
	name  string
	warns []error
	errs  []error
}

func (f *fakeValidator) Name() string {
	return f.name
}

func (f *fakeValidator) Validate(_ SysSpec) ([]error, []error) {
	return f.warns, f.errs
}

func TestValidateNoValidators(t *testing.T) {
	warns, errs := Validate(SysSpec{}, nil)
	if len(warns) != 0 || len(errs) != 0 {
		t.Fatalf("expected no warnings or errors, got warns=%v errs=%v", warns, errs)
	}
}

func TestValidateAggregatesAcrossValidators(t *testing.T) {
	v1 := &fakeValidator{name: "clean"}
	v2 := &fakeValidator{name: "warn-only", warns: []error{errors.New("w1")}}
	v3 := &fakeValidator{name: "err-only", errs: []error{errors.New("e1")}}
	v4 := &fakeValidator{
		name:  "warn-and-err",
		warns: []error{errors.New("w2")},
		errs:  []error{errors.New("e2")},
	}

	warns, errs := Validate(SysSpec{}, []Validator{v1, v2, v3, v4})

	if len(warns) != 2 {
		t.Fatalf("expected 2 warnings, got %d: %v", len(warns), warns)
	}
	if warns[0].Error() != "w1" || warns[1].Error() != "w2" {
		t.Errorf("unexpected warning order/content: %v", warns)
	}

	if len(errs) != 2 {
		t.Fatalf("expected 2 errors, got %d: %v", len(errs), errs)
	}
	if errs[0].Error() != "e1" || errs[1].Error() != "e2" {
		t.Errorf("unexpected error order/content: %v", errs)
	}
}

func TestValidateStopsOnNeitherErrorNorWarning(t *testing.T) {
	v1 := &fakeValidator{name: "clean-1"}
	v2 := &fakeValidator{name: "clean-2"}

	warns, errs := Validate(SysSpec{}, []Validator{v1, v2})

	if warns != nil {
		t.Errorf("expected nil warnings, got %v", warns)
	}
	if errs != nil {
		t.Errorf("expected nil errors, got %v", errs)
	}
}

func TestValidateSpecReturnsWithoutPanicking(t *testing.T) {
	tests := []string{"", "docker", "containerd", "unknown-runtime"}

	for _, cr := range tests {
		t.Run(cr, func(t *testing.T) {
			// An empty SysSpec has a nil DockerSpec, so even when containerRuntime
			// is "docker" the DockerValidator skips shelling out to the docker CLI.
			warns, errs := ValidateSpec(SysSpec{}, cr)
			for _, w := range warns {
				if w == nil {
					t.Errorf("got a nil warning in result for containerRuntime %q", cr)
				}
			}
			for _, e := range errs {
				if e == nil {
					t.Errorf("got a nil error in result for containerRuntime %q", cr)
				}
			}
		})
	}
}
