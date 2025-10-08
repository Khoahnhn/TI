package model

import (
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
)

func TestFeature_GetID(t *testing.T) {
	tests := []struct {
		name    string
		wantNil bool
	}{
		{
			name:    "should return interface",
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &Feature{}
			result := doc.GetID()

			if result == nil && !tt.wantNil {
				t.Errorf("GetID() returned nil")
			}
		})
	}
}

func TestFeature_GenID(t *testing.T) {
	tests := []struct {
		name        string
		featureName string
	}{
		{
			name:        "generate ID with normal name",
			featureName: "Test Feature",
		},
		{
			name:        "generate ID with empty name",
			featureName: "",
		},
		{
			name:        "generate ID with special characters",
			featureName: "Feature@#$%^&*()",
		},
		{
			name:        "generate ID with Vietnamese",
			featureName: "Tính năng tiếng Việt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &Feature{}
			doc.Name = tt.featureName
			doc.GenID()
		})
	}
}

func TestRequestFeatureList_Query(t *testing.T) {
	tests := []struct {
		name     string
		body     *RequestFeatureList
		expected bson.M
	}{
		{
			name: "empty request should return empty filter",
			body: &RequestFeatureList{
				Keyword:       "",
				ParentFeature: "",
			},
			expected: bson.M{},
		},
		{
			name: "with keyword only",
			body: &RequestFeatureList{
				Keyword:       "test",
				ParentFeature: "",
			},
			expected: bson.M{
				"$or": bson.A{
					bson.M{"name": bson.M{"$regex": "test", "$options": "i"}},
					bson.M{"code": bson.M{"$regex": "test", "$options": "i"}},
				},
			},
		},
		{
			name: "with ParentFeature only",
			body: &RequestFeatureList{
				Keyword:       "",
				ParentFeature: "PARENT_CODE",
			},
			expected: bson.M{
				"ancestors": "PARENT_CODE",
			},
		},
		{
			name: "with both keyword and ParentFeature",
			body: &RequestFeatureList{
				Keyword:       "search",
				ParentFeature: "PARENT_CODE",
			},
			expected: bson.M{
				"$or": bson.A{
					bson.M{"name": bson.M{"$regex": "search", "$options": "i"}},
					bson.M{"code": bson.M{"$regex": "search", "$options": "i"}},
				},
				"ancestors": "PARENT_CODE",
			},
		},
		{
			name: "keyword with special regex characters",
			body: &RequestFeatureList{
				Keyword:       "test.*[a-z]",
				ParentFeature: "",
			},
			expected: bson.M{
				"$or": bson.A{
					bson.M{"name": bson.M{"$regex": `test\.\*\[a-z\]`, "$options": "i"}},
					bson.M{"code": bson.M{"$regex": `test\.\*\[a-z\]`, "$options": "i"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.body.Query()
			assert.NotNil(t, result)
			if len(tt.expected) == 0 {
				assert.Equal(t, 0, len(*result), "Filter should be empty")
			} else {
				if tt.body.ParentFeature != "" {
					assert.Equal(t, tt.body.ParentFeature, (*result)["ancestors"])
				}
				if tt.body.Keyword != "" {
					assert.Contains(t, *result, "$or")
					orConditions := (*result)["$or"].(bson.A)
					assert.Equal(t, 2, len(orConditions))
				}
			}
		})
	}
}
