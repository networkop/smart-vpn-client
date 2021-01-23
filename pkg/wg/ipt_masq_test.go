package wg

import (
	"testing"
)

func TestIPtables(t *testing.T) {
	wg, err := New()
	if err != nil {
		t.Fatal(err)
	}

	wg.intfName = "wg-package-test"

	tests := []struct {
		name    string
		command func() (string, error)
		wantOut string
		wantErr bool
	}{
		{
			name:    "first",
			command: wg.getIPtables,
			wantOut: "",
			wantErr: true,
		},
		{
			name:    "second",
			command: wg.addIPtables,
			wantOut: "",
			wantErr: false,
		},
		{
			name:    "third",
			command: wg.getIPtables,
			wantOut: "",
			wantErr: false,
		},
		{
			name:    "fourth",
			command: wg.delIPtables,
			wantOut: "",
			wantErr: false,
		},
		{
			name:    "fifth",
			command: wg.delIPtables,
			wantOut: "iptables: No chain/target/match by that name.\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.command()

			if (err != nil) != tt.wantErr {
				t.Errorf("%s test error = %v, wantErr %v", tt.name, err, tt.wantErr)
			} else if out != tt.wantOut {
				t.Errorf("Want: '%s', Got: '%s'", tt.wantOut, out)
			}

		})
	}
}
