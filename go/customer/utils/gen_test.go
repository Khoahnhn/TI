package utils

import (
	"testing"
)

func TestGenID(t *testing.T) {
	type args struct {
		resourceType string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "bad_resource_type",
			args: args{
				resourceType: "foo",
			},
			wantErr: true,
		},
		{
			name: "resource_type_intel",
			args: args{
				resourceType: "intel",
			},
			wantErr: false,
		},
		{
			name: "resource_type_intel",
			args: args{
				resourceType: "api_key",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenID(tt.args.resourceType)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGenConfirmMail(t *testing.T) {
	type args struct {
		resourceType string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "bad_resource_type",
			args: args{
				resourceType: "foo",
			},
			wantErr: true,
		},
		{
			name: "role",
			args: args{
				resourceType: "role",
			},
			wantErr: false,
		},
		{
			name: "api_key",
			args: args{
				resourceType: "api_key",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenConfirmMail(tt.args.resourceType)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenConfirmMail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
