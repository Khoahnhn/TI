package utils

import (
	"reflect"
	"testing"
)

func TestSliceContains(t *testing.T) {
	type args struct {
		s []any
		e any
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "true",
			args: args{
				s: []any{"a", "b"},
				e: "a",
			},
			want: true,
		},
		{
			name: "false",
			args: args{
				s: []any{"a", "b"},
				e: "c",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SliceContains(tt.args.s, tt.args.e); got != tt.want {
				t.Errorf("SliceContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapKeysToSlice(t *testing.T) {
	type args struct {
		mp map[any]any
	}
	tests := []struct {
		name string
		args args
		want []any
	}{
		{
			name: "happy",
			args: args{
				mp: map[any]any{
					"a": 1,
				},
			},
			want: []any{"a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MapKeysToSlice(tt.args.mp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapKeysToSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
