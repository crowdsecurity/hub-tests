package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

type SingleItemTested struct {
	count     int
	failCount int
}

type Overall struct {
	overall map[string]map[string]SingleItemTested
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
		return fmt.Errorf("Marshal %s error: %s, filename", filename, err)
	}
	if err = ioutil.WriteFile(filename, out, 0644); err != nil {
		return fmt.Errorf("Write file %s error: %s", filename, err)
	}
	return nil
}

// be cautious to pass a pointer in the interface
func retrieveAndUnmarshal(filename string, b interface{}) error {
	var (
		buf []byte
		err error
	)
	if buf, err = ioutil.ReadFile(filename); err != nil {
		return fmt.Errorf("Read file %s error: %s", filename, err)
	}
	if err = yaml.Unmarshal(buf, b); err != nil {
		return fmt.Errorf("Unmarshal file %s error: %s", filename, err)
	}
	return nil
}

func NewOverall() *Overall {
	return &Overall{
		overall: make(map[string]map[string]SingleItemTested),
	}
}

func (o *Overall) AddSingleResult(tested map[string][]string, failure bool) {
	for itemType, itemList := range tested {
		if _, ok := o.overall[itemType]; !ok {
			o.overall[itemType] = make(map[string]SingleItemTested)
		}
		for _, item := range itemList {
			if _, ok := o.overall[itemType][item]; !ok {
				if failure {
					o.overall[itemType][item] = SingleItemTested{
						count:     1,
						failCount: 1,
					}
				} else {
					o.overall[itemType][item] = SingleItemTested{
						count:     1,
						failCount: 0,
					}
				}
			} else {
				if failure {
					tmp := o.overall[itemType][item]
					tmp.count++
					tmp.failCount++
					o.overall[itemType][item] = tmp
				} else {
					tmp := o.overall[itemType][item]
					tmp.count++
					o.overall[itemType][item] = tmp
				}
			}
		}
	}
}

func buildOverallResult(dir string) (map[string]map[string]Configuration, error) {
	ret := make(map[string]map[string]Configuration)
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if strings.Contains(path, ".tests") {
			return nil
		}

		if f.Mode().IsDir() {
			return nil
		}

		parts := strings.Split(path, "/")
		if parts[0] != "parsers" && parts[0] != "scenarios" && parts[0] != "postoverflows" {
			return nil
		}

		npath := ""

		if parts[0] == "parsers" || parts[0] == "postoverflows" {
			npath = strings.Join(parts[2:], "/")
		}
		if parts[0] == "scenarios" && len(parts) > 1 {
			npath = strings.Join(parts[1:], "/")
		}

		if _, ok := ret[parts[0]]; !ok {
			ret[parts[0]] = make(map[string]Configuration)
		}
		if filepath.Ext(npath) == ".md" {
			var c Configuration
			entry := strings.TrimSuffix(npath, ".md")
			if _, ok := ret[parts[0]][entry]; ok {
				c = ret[parts[0]][entry]
			} else {
				c = Configuration{}
			}
			c.markdown = true
			if f.Size() == 0 {
				c.markdownNotEmpty = false
				ret[parts[0]][entry] = c
			} else {
				c.markdownNotEmpty = true
				ret[parts[0]][entry] = c
			}
		}

		if filepath.Ext(npath) == ".yaml" {
			entry := strings.TrimSuffix(npath, ".yaml")
			if _, ok := ret[parts[0]][entry]; !ok {
				ret[parts[0]][entry] = Configuration{
					markdown:         false,
					markdownNotEmpty: false,
					count:            0,
					failure:          0,
				}
			}
		}
		return nil
	})
	return ret, err
}
