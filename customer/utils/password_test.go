package utils

import (
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "happy_case",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd := GeneratePassword()
			if len(pwd) < 8 || len(pwd) > 12 {
				t.Errorf("expected password of len [8, 12], got len %v", len(pwd))
			}
		})
	}
}

func TestGeneratePasswordHash(t *testing.T) {
	type args struct {
		password   string
		method     string
		saltLength int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "empty_method",
			args: args{
				password:   "1234",
				method:     "",
				saltLength: 0,
			},
		},
		{
			name: "plain",
			args: args{
				password:   "1234",
				method:     "plain",
				saltLength: 0,
			},
		},
		{
			name: "sha256",
			args: args{
				password:   "1234",
				method:     "sha256",
				saltLength: 0,
			},
		},
		{
			name: "sha512",
			args: args{
				password:   "1234",
				method:     "sha512",
				saltLength: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GeneratePasswordHash(tt.args.password, tt.args.method, tt.args.saltLength)
		})
	}
}
