package model

import (
	"go.mongodb.org/mongo-driver/bson"
	"reflect"
	"testing"
)

func TestRequestGetPermissions_BuildQuery(t *testing.T) {
	tests := []struct {
		name   string
		input  RequestGetPermissions
		expect bson.M
	}{
		{
			name:   "Empty request",
			input:  RequestGetPermissions{},
			expect: bson.M{},
		},
		{
			name: "Module only",
			input: RequestGetPermissions{
				Module: "user_management",
			},
			expect: bson.M{
				"module_id": "user_management",
			},
		},
		{
			name: "Keyword only",
			input: RequestGetPermissions{
				Keyword: "Abc",
			},
			expect: bson.M{
				"$or": []bson.M{
					{"permission_id": bson.M{"$regex": "Abc", "$options": "i"}},
					{"description": bson.M{"$regex": "Abc", "$options": "i"}},
				},
			},
		},
		{
			name: "Keyword with special chars",
			input: RequestGetPermissions{
				Keyword: "test*pattern",
			},
			expect: bson.M{
				"$or": []bson.M{
					{"permission_id": bson.M{"$regex": "test\\*pattern", "$options": "i"}},
					{"description": bson.M{"$regex": "test\\*pattern", "$options": "i"}},
				},
			},
		},
		{
			name: "Both Module and Keyword",
			input: RequestGetPermissions{
				Module:  "user_management",
				Keyword: "create",
			},
			expect: bson.M{
				"module_id": "user_management",
				"$or": []bson.M{
					{"permission_id": bson.M{"$regex": "create", "$options": "i"}},
					{"description": bson.M{"$regex": "create", "$options": "i"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.BuildQuery()
			if !reflect.DeepEqual(result, tt.expect) {
				t.Errorf("BuildQuery() = %+v, want %+v", result, tt.expect)
			}
		})
	}
}

func TestRequestGetPermissions_BuildPagination(t *testing.T) {
	tests := []struct {
		name               string
		s                  RequestGetPermissions
		wantOffset, wantSz int64
	}{
		{
			name:       "size and offset positive",
			s:          RequestGetPermissions{Size: 20, Offset: 5},
			wantOffset: 5, wantSz: 20,
		},
		{
			name:       "size zero -> default 10",
			s:          RequestGetPermissions{Size: 0, Offset: 3},
			wantOffset: 3, wantSz: 10,
		},
		{
			name:       "offset negative -> 0",
			s:          RequestGetPermissions{Size: 15, Offset: -1},
			wantOffset: 0, wantSz: 15,
		},
		{
			name:       "both invalid -> default size 10 and offset 0",
			s:          RequestGetPermissions{Size: 0, Offset: -10},
			wantOffset: 0, wantSz: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOffset, gotSize := tt.s.BuildPagination()
			if gotOffset != tt.wantOffset || gotSize != tt.wantSz {
				t.Fatalf("BuildPagination() = (offset=%d,size=%d), want (offset=%d,size=%d)",
					gotOffset, gotSize, tt.wantOffset, tt.wantSz)
			}
		})
	}
}

func TestPermissions_GetID(t *testing.T) {
	doc := &Permissions{ID: "custom-id"}
	if got := doc.GetID(); got != "custom-id" {
		t.Fatalf("GetID() = %q, want %q", got, "custom-id")
	}
}

func TestPermissions_GenID(t *testing.T) {
	p := &Permissions{PermissionId: "perm-123"}
	p.GenID()
	id1 := p.GetID()
	p.PermissionId = "perm-456"
	p.GenID()
	id2 := p.GetID()
	if id1 == id2 {
		t.Fatalf("GenID should produce different ids for different PermissionId: %q == %q", id1, id2)
	}
}
