package wg

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRules(t *testing.T) {
	wg, err := New()
	if err != nil {
		t.Fatal(err)
	}

	wg.intfName = "wg-package-test"

	tests := []struct {
		name          string
		changeCommand func() error
		getCommand    func() *netlink.Rule
		wantRule      bool
	}{
		{
			name:          "first",
			changeCommand: wg.addLocalRule,
			getCommand:    wg.getLocalRule,
			wantRule:      true,
		},
		{
			name:          "second",
			changeCommand: wg.addDefaultRule,
			getCommand:    wg.getDefaultRule,
			wantRule:      true,
		},
		{
			name:          "third",
			changeCommand: wg.delLocalRule,
			getCommand:    wg.getLocalRule,
			wantRule:      false,
		},
		{
			name:          "fourth",
			changeCommand: wg.delDefaultRule,
			getCommand:    wg.getDefaultRule,
			wantRule:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.changeCommand()

			if err != nil {
				t.Errorf("%s test error = %v", tt.name, err)
			} else {
				rule := tt.getCommand()
				if (rule != nil) != tt.wantRule {
					t.Errorf("%s test error, wantRule: %v", tt.name, tt.wantRule)
				}
			}

		})
	}
}
