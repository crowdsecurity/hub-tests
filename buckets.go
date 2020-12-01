package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

//sort alert for each overflow
func sortAlerts(event types.Event) types.Event {
	//copy the slice
	if event.Overflow.APIAlerts == nil {
		return event
	}
	for index, alert := range event.Overflow.APIAlerts {
		for i, evt := range alert.Events {
			meta := evt.Meta
			sort.Slice(meta, func(i, j int) bool {
				return meta[i].Key < meta[j].Key
			})
			event.Overflow.APIAlerts[index].Events[i].Meta = meta
		}
	}
	return event
}

func newBuckets(index map[string]map[string]cwhub.Item, local ConfigTest) []string {
	var (
		files []string = []string{}
	)
	for _, itemType := range []string{cwhub.SCENARIOS} {
		for _, hubParserName := range local.Configurations[itemType] {
			files = append(files, index[itemType][hubParserName].RemotePath)
		}
	}
	return files
}

// for now we still use the bool to say if the test was ok
func testBucketsOutput(target_dir string, AllBucketsResult []types.Event) error {
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
			return errors.Wrapf(err, "file %s can't be unmarshaled : %s", expectedResultsFile)
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
			return errors.Wrap(err, "failed to marshal results")
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			return errors.Wrapf(err, "failed to dump data to %s : %s", expectedResultsFile)
		}
	} else {
		if len(AllBucketsExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllBucketsExpected))
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
			return errors.Wrap(err, "failed to marshal result")
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			return errors.Wrapf(err, "failed to dump data to %s : %s", expectedResultsFile)
		}
		log.Printf("done")
		err = errors.New(cmp.Diff(AllBucketsExpected, AllBucketsResult, opt))
		return errors.WithMessage(err, "mismatch diff (-want +got)")
	}

	if !matched && len(AllBucketsExpected) != 0 {
		expectedResultsFile = expectedResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedResultsFile)
		dump_bytes, err := json.MarshalIndent(AllBucketsResult, "", " ")
		if err != nil {
			errors.Wrap(err, "failed to marshal results")
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			errors.Wrapf(err, "failed to dump data to %s", expectedResultsFile)
		}
		log.Printf("done")
		return errors.New("Result is not in the expected results")

	}
	log.Infof("%d/%d matched results", OrigExpectedLen-len(AllBucketsExpected), OrigExpectedLen)
	log.Infof("Bucket tets are finished")
	return nil

}

func testBuckets(target_dir string, cConfig *csconfig.GlobalConfig, localConfig ConfigTest) error {
	var (
		potomb        tomb.Tomb
		bucketsOutput []types.Event = []types.Event{}
		bucketsInput  []types.Event = []types.Event{}
		err           error
	)

	// Retrieve value from yaml
	// And once again we would have done better with generics...
	if err = retrieveAndUnmarshal(target_dir+"/"+localConfig.bucketInputFile, &bucketsInput); err != nil {
		return fmt.Errorf("Error unmarshaling %s: %s", localConfig.bucketInputFile, err)
	}

	overflow := 0
	//	unparsedOverflow := 0
	potomb.Go(func() error {
		log.Printf("processing loop over postoveflow")
		for {
			select {
			case event, ok := <-outputEventChan:
				if !ok {
					return nil
				}
				log.Printf("An overflow happened")
				overflow++
				bucketsOutput = append(bucketsOutput, sortAlerts(event))
			case <-potomb.Dying():
				return nil
			}

		}
	})

	for index, parsed := range bucketsInput {
		log.Printf("Pouring item %d", index+1)
		_, err = leaky.PourItemToHolders(parsed, holders, buckets)
		if err != nil {
			return errors.New(fmt.Sprintf("bucketify failed for: %v", parsed))
		}
	}

	//this should be taken care of
	time.Sleep(5 * time.Second)

	if err := testBucketsOutput(target_dir, bucketsOutput); err != nil {
		return errors.Wrap(err, "Buckets error: %s")
	}

	close(outputEventChan)

	log.Printf("Waiting for bucket tomb to die")
	if err := potomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	if err := marshalAndStore(bucketsOutput, target_dir+"/"+localConfig.poInputFile); err != nil {
		return errors.Wrap(err, "marshaling failed")
	}

	return nil
}
