package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

//sort alert for each overflow
func sortAlerts(event types.Event) types.Event {
	//copy the slice
	if event.Overflow.APIAlerts == nil {
		return event
	}
	//	tmp := append([]models.Alert{}, event.Overflow.APIAlerts...)
	//	log.Printf("meta1: %+v", event)
	for index, alert := range event.Overflow.APIAlerts {
		for i, evt := range alert.Events {
			meta := evt.Meta
			sort.Slice(meta, func(i, j int) bool {
				return meta[i].Key < meta[j].Key
			})
			//			log.Printf("meta2: %+v", meta)
			event.Overflow.APIAlerts[index].Events[i].Meta = meta
		}
	}
	return event
}

func testBucketsOutput(target_dir string, AllBucketsResult []types.Event) (bool, error) {
	var (
		OrigExpectedLen    int
		AllBucketsExpected []types.Event = []types.Event{}
	)
	//load the expected results
	ExpectedPresent := false
	expectedResultsFile := target_dir + "/buckets_results.json"
	expected_bytes, err := ioutil.ReadFile(expectedResultsFile)
	if err != nil {
		log.Warningf("no buckets result in %s, will dump data instead!", target_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllBucketsExpected); err != nil {
			return false, fmt.Errorf("file %s can't be unmarshaled : %s", expectedResultsFile, err)
		} else {
			ExpectedPresent = true
			OrigExpectedLen = len(AllBucketsExpected)
		}
	}
	//there was no data present, just dump
	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllBucketsResult, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
	} else {
		if len(AllExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllExpected))
		}
	}

	//from here we will deal with postoverflow
	opt := getCmpOptions()
	matched := false
	if cmp.Equal(AllBucketsExpected, AllBucketsResult, opt) {
		matched = true
	} else {
		expectedResultsFile = expectedResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedResultsFile)
		dump_bytes, err := json.MarshalIndent(AllBucketsResult, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
		log.Printf("done")
		return false, fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(AllBucketsExpected, AllBucketsResult, opt))
	}

	if !matched && len(AllExpected) != 0 {
		expectedResultsFile = expectedResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedResultsFile)
		dump_bytes, err := json.MarshalIndent(AllBucketsResult, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
		log.Printf("done")
		return false, fmt.Errorf("Result is not in the %d expected results", len(AllExpected))

	}
	log.Infof("%d/%d matched results", OrigExpectedLen-len(AllBucketsExpected), OrigExpectedLen)
	log.Infof("Bucket tets are finished")
	return true, nil

}
