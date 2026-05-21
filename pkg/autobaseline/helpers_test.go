package autobaseline

import "github.com/xhelix/xhelix/pkg/model"

func mkEvent(sensor string, tags map[string]string) model.Event {
	e := model.NewEvent(sensor, model.SeverityInfo)
	for k, v := range tags {
		e.Tags[k] = v
	}
	return e
}
