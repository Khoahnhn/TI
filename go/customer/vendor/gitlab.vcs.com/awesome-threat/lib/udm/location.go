package udm

import (
	"fmt"
	"strings"
)

type (
	Location struct {
		City              string  `json:"city,omitempty"`
		CountryOrRegion   string  `json:"country_or_region,omitempty"`
		ContinentCode     string  `json:"continent_code,omitempty"`
		ContinentName     string  `json:"continent_name,omitempty"`
		DeskName          string  `json:"desk_name,omitempty"`
		FloorName         string  `json:"floor_name,omitempty"`
		Name              string  `json:"name,omitempty"`
		State             string  `json:"state,omitempty"`
		RegionCoordinates *LatLng `json:"region_coordinates,omitempty"`
	}

	LatLng struct {
		Latitude  float64 `json:"latitude,omitempty"`
		Longitude float64 `json:"longitude,omitempty"`
	}
)

func (inst *Location) Flatten() map[string]interface{} {
	flattened := make(map[string]interface{})

	locations := make([]string, 0)
	for _, location := range []string{inst.DeskName, inst.FloorName, inst.Name, inst.City, inst.State} {
		if len(location) > 0 {
			locations = append(locations, location)
		}
	}
	if len(locations) > 0 {
		flattened["Location"] = strings.Join(locations, ",")
	}

	if inst.RegionCoordinates != nil {
		flattened["Coordinates"] = fmt.Sprintf("%f, %f", inst.RegionCoordinates.Latitude, inst.RegionCoordinates.Longitude)
	}
	// Success
	return flattened
}
