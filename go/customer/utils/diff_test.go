package utils

import (
	"reflect"
	"testing"
)

func TestGetChangedFieldsJson(t *testing.T) {
	type args struct {
		old  []byte
		new  []byte
		keys []string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]DiffField
		wantErr bool
	}{
		{
			name: "corrupted_old",
			args: args{
				old:  []byte("{{none"),
				new:  []byte("{\"a\": 1}"),
				keys: []string{"a"},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "corrupted_new",
			args: args{
				old:  []byte("{\"a\": 1}"),
				new:  []byte("{{none"),
				keys: []string{"a"},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "happy_case",
			args: args{
				old:  []byte("{\"a\": 1, \"b\": 3}"),
				new:  []byte("{\"a\": 2}"),
				keys: []string{"a", "b"},
			},
			want:    map[string]DiffField{
				"a": {
					Before: float64(1),
					After:  float64(2),
				},
				"b": {
					Before: float64(3),
					After:  nil,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetChangedFieldsJson(tt.args.old, tt.args.new, tt.args.keys)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetChangedFieldsJson() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetChangedFieldsJson() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
