package model

import (
	"fmt"
	"strings"
	"time"
)

type BrandAbuseAlert struct {
	DomainID     string    `bson:"d_id"`
	Domain       string    `bson:"domain"`
	Name         string    `bson:"name"`
	CreationTime time.Time `bson:"creation_time"`
	MonitorTime  time.Time `bson:"monitor_time"`
	Target       []string  `bson:"target"`
	Category     string    `bson:"category"`
}

func (doc *BrandAbuseAlert) GetID() interface{} {
	// Success
	return doc.DomainID
}

func (doc *BrandAbuseAlert) Plain() string {
	paths := strings.Split(doc.Domain, ".")
	if len(paths) >= 2 {
		paths[len(paths)-1] = fmt.Sprintf("]%s", paths[len(paths)-1])
		paths[len(paths)-2] = fmt.Sprintf("%s[", paths[len(paths)-2])
	}
	// Success
	return strings.Join(paths, ".")
}
