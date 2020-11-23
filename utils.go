package main

import (
	"reflect"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
)

func getCmpOptions() cmp.Option {
	/*
	** we are using cmp's feature to match structures.
	** because of the way marshal/unmarshal works we want to make nil == empty
	 */
	// This option handles slices and maps of any type.
	alwaysEqual := cmp.Comparer(func(_, _ interface{}) bool { return true })
	opt := cmp.FilterValues(func(x, y interface{}) bool {
		vx, vy := reflect.ValueOf(x), reflect.ValueOf(y)
		return (vx.IsValid() && vy.IsValid() && vx.Type() == vy.Type()) &&
			(vx.Kind() == reflect.Slice || vx.Kind() == reflect.Map) &&
			(vx.Len() == 0 && vy.Len() == 0)
	}, alwaysEqual)
	return opt
}

//cleanForMatch : cleanup results from items that might change every run. We strip as well strictly equal results
func cleanForMatch(in map[string]map[string]types.Event) map[string]map[string]types.Event {
	for stage, val := range in {
		for parser, evt := range val {
			evt.Line.Time = time.Time{}
			evt.Time = time.Time{}
			in[stage][parser] = evt
		}
	}
	return in
}
