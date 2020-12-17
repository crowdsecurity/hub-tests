package main

import (
	"fmt"
	"io/ioutil"
	"sort"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
func testBucketsResults(testFile string, results []types.Event) error {
	var (
		expected []types.Event = []types.Event{}
		err      error
	)
	//load the expected results
	ExpectedPresent := false
	log.Debugf("looking for testresults in %s", testFile)
	_, err = ioutil.ReadFile(testFile)
	if err != nil {
		log.Warningf("no result in %s, will dump data instead!", testFile)
	} else {
		err = retrieveAndUnmarshal(testFile, &expected)
		if err == nil {
			ExpectedPresent = true
		} else {
			return errors.Wrapf(err, "Unable to unmarsharl %s", testFile)
		}
		//there was no data present, just dump
	}

	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		marshalAndStore(results, testFile)
		return nil
	}

	return TestResults(expected, results, testFile+".fail", "buckets", true)
}

func testBuckets(cConfig *csconfig.GlobalConfig, localConfig ConfigTest) error {
	var (
		btomb         tomb.Tomb
		bucketsOutput []types.Event = []types.Event{}
		bucketsInput  []types.Event = []types.Event{}
		err           error
	)

	// Retrieve value from yaml
	// And once again we would have done better with generics...
	if err = retrieveAndUnmarshal(localConfig.targetDir+"/"+localConfig.BucketInputFile, &bucketsInput); err != nil {
		var tmp ParserResults
		if err2 := retrieveAndUnmarshal(localConfig.targetDir+"/"+localConfig.ParserResultFile, &tmp); err2 != nil {
			return errors.New(fmt.Sprintf("unable to find any data to feed to the buckets: %s, %s", err, err2))
		}
		bucketsInput = tmp.FinalResults
	}

	overflow := 0
	//bucket goroutine
	btomb.Go(func() error {
		for {
			select {
			case event, ok := <-outputEventChan:
				if !ok {
					return nil
				}
				log.Printf("An overflow happened")
				overflow++
				bucketsOutput = append(bucketsOutput, sortAlerts(event))
			case <-btomb.Dying():
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

	time.Sleep(5 * time.Second) // get rid of this later, but this ensure pr
	//Ensure all the LeakRoutine are dead and that overflow had enough time to happened
	// TODO: fix the race by adding a way to know how much Leakroutine are alive
	for leaky.LeakyRoutineCount > 1 {
		time.Sleep(50 * time.Millisecond)
	}

	//kill and wait for the bucket goroutine
	btomb.Kill(nil)
	log.Printf("Waiting for bucket tomb to die")
	if err := btomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	bucketsOutput = cleanBucketOutput(bucketsOutput)
	if err := testBucketsResults(localConfig.targetDir+"/"+localConfig.BucketResultFile, bucketsOutput); err != nil {
		return errors.Wrap(err, "Buckets error: %s")
	}

	if err := marshalAndStore(bucketsOutput, localConfig.targetDir+"/"+localConfig.PoInputFile); err != nil {
		return errors.Wrap(err, "marshaling failed")
	}

	return nil
}

func cleanBucketOutput(events []types.Event) []types.Event {
	var (
		output []types.Event = []types.Event{}
	)
	for _, event := range events {
		var alerts []models.Alert = []models.Alert{}
		for _, alert := range event.Overflow.APIAlerts {
			*alert.Message = ""
			*alert.StartAt = (time.Time{}).Format(time.RFC3339)
			*alert.StopAt = (time.Time{}).Format(time.RFC3339)
			alerts = append(alerts, alert)
		}
		event.Overflow.APIAlerts = alerts
		// In some cases the alerts slice can be empty:
		// * blackhole
		// * unusual scope
		if len(event.Overflow.APIAlerts) > 0 {
			event.Overflow.Alert = &event.Overflow.APIAlerts[0]
		}
		event.MarshaledTime = (time.Time{}).Format(time.RFC3339)
		output = append(output, event)
	}
	return output
}
