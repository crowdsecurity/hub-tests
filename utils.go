package main

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v2"
)

type UniqDescriptor interface {
}

type Result interface {
	Discriminate(interface{}) bool
	DeepEqual(map[string]map[string]types.Event) bool
}

type LineResult struct {
	string
	LineResult map[string]map[string]types.Event
}

func (s *LineResult) Discriminate(e string) bool {
	return s.string == e
}

func (s *LineResult) DeepEqual(result map[string]map[string]types.Event) bool {
	return cmp.Equal(s.LineResult, result, getCmpOptions())
}

type Overflow struct {
	types.RuntimeAlert
	OverflowResult map[string]map[string]types.Event
}

func (o *Overflow) Discriminate(e types.RuntimeAlert) bool {
	return cmp.Equal(o.RuntimeAlert, e, getCmpOptions())
}

func (o *Overflow) DeepEqual(result map[string]map[string]types.Event) bool {
	return cmp.Equal(o.OverflowResult, result, getCmpOptions())
}

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

func marshalAndStore(in interface{}, filename string) error {
	var (
		out []byte
		err error
	)
	if out, err = yaml.Marshal(in); err != nil {
		return fmt.Errorf("Marshal %s error: %s, filename", err)
	}
	if err = ioutil.WriteFile(filename, out, 0644); err != nil {
		return fmt.Errorf("Write file %s error: %s, filename", err)
	}
	return nil
}

func retrieveAndUnmarshal(filename string) (interface{}, error) {
	var (
		out interface{}
		buf []byte
		err error
	)
	if buf, err = ioutil.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("Read file %s error: %s", filename, err)
	}
	if err = yaml.Unmarshal(buf, &out); err != nil {
		return nil, fmt.Errorf("Unmarshal file %s error: %s", filename, err)
	}
	return out, nil
}
