package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var (
	acquisTomb tomb.Tomb

	AllResults    []LineParseResult
	AllExpected   []LineParseResult
	AllPoResults  []LineParsePoResult
	AllPoExpected []LineParsePoResult

	holders []leaky.BucketFactory
	buckets *leaky.Buckets

	outputEventChan chan types.Event
)

type LineParseResult struct {
	Line          string
	ParserResults map[string]map[string]types.Event
}

type LineParsePoResult struct {
	Overflow      types.RuntimeAlert
	ParserResults map[string]map[string]types.Event
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

func testOneDir(target_dir string, parsers *parser.Parsers, cConfig *csconfig.GlobalConfig) (bool, error) {
	var (
		err             error
		acquisitionCTX  *acquisition.FileAcquisCtx
		inputLineChan   = make(chan types.Event)
		failure         bool
		OrigExpectedLen int
		tmpctx          []acquisition.FileCtx
		ptomb, potomb   tomb.Tomb
		bucketsInput    []types.Event = []types.Event{}
		bucketsOutput   []types.Event
	)

	log.Infof("Loading acquisition")
	tmpctx, err = acquisition.LoadAcquisCtxConfigFile(cConfig.Crowdsec)
	if err != nil {
		log.Fatalf("Not able to init acquisition")
	}
	for _, filectx := range tmpctx {
		if filectx.Mode != "cat" {
			log.Warning("The mode of reading the log file '%s' is not 'cat'. The whole thing is highly probably bound to fail", filectx.Filename)
		}
	}

	acquisitionCTX, err = acquisition.InitReaderFromFileCtx(tmpctx)
	if err != nil {
		log.Fatalf("Not able to init acquisition")
	}

	//load parsers
	log.Infof("Loading parsers")
	//load the expected results
	ExpectedPresent := false
	expectedResultsFile := target_dir + "/parser_results.json"
	expected_bytes, err := ioutil.ReadFile(expectedResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", target_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllExpected); err != nil {
			return false, fmt.Errorf("file %s can't be unmarshaled : %s", expectedResultsFile, err)
		} else {
			ExpectedPresent = true
			OrigExpectedLen = len(AllExpected)
		}
	}

	//start reading in the background
	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	linesRead := 0
	linesUnparsed := 0
	testsFailed := 0

	parser.ParseDump = true
	ptomb = tomb.Tomb{}
	potomb = tomb.Tomb{}
	// ptomb.Go(func() error {

	ptomb.Go(func() error {
		log.Printf("Processing logs")
		for {
			select {
			case event, ok := <-inputLineChan:
				if !ok {
					return nil
				}
				log.Printf("one line")
				linesRead++
				test_ok, parsed_ok, parsed, err := parseMatchLine(event, parsers.Ctx, parsers.Nodes)
				bucketsInput = append(bucketsInput, parsed)
				log.Printf("done")
				if !parsed_ok {
					if err != nil {
						log.Warningf("parser error : %s", err)
					}
					linesUnparsed++
				}
				if !test_ok {
					failure = true
					// TODO: estsFailed++
					log.Errorf("test %d failed.", linesRead)
					if err != nil {
						log.Errorf("test failure : %s", err)
					}
				}
			case <-ptomb.Dying():
				return nil
			}
		}
	})

	log.Printf("waiting for acquis tomb to die")
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}
	log.Printf("acquis tomb died")

	//We close the log chan, and waiting the tomb to die, to be sure not to forget event in the cloud
	close(inputLineChan)
	log.Printf("Waiting for parsers tomb to die")
	if err := ptomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	overflow := 0
	unparsedOverflow := 0
	potomb.Go(func() error {
		log.Printf("processing loop over postoveflow")
		for {
			select {
			case event, ok := <-outputEventChan:
				if !ok {
					return nil
				}
				log.Printf("one overflow")
				overflow++
				bucketsOutput = append(bucketsOutput, sortAlerts(event))
				parsed_ok, err := parsePoMatchLine(event, parsers.Povfwctx, parsers.Povfwnodes)
				if !parsed_ok {
					if err != nil {
						log.Warningf("parser error : %s", err)
					}
					unparsedOverflow++
				}
			case <-potomb.Dying():
				return nil
			}

		}
		return nil
	})

	log.Infof("Pouring buckets")
	for index, parsed := range bucketsInput {
		log.Printf("Pouring item %d", index+1)
		_, err = leaky.PourItemToHolders(parsed, holders, buckets)
		if err != nil {
			log.Fatalf("bucketify failed for: %v", parsed)
		}
	}

	//this should be taken care of
	time.Sleep(5 * time.Second)

	//parser result analysis
	log.Infof("%d lines read", linesRead)
	log.Infof("%d parser results, %d UNPARSED", len(AllResults), linesUnparsed)
	if linesRead != len(AllResults) {
		log.Warningf("%d out of %d lines didn't yeld result", linesRead-len(AllResults), linesRead)
	}
	log.Infof("%d/%d matched results", OrigExpectedLen-len(AllExpected), OrigExpectedLen)
	if len(AllExpected) > 0 {
		log.Warningf("%d out of %d expected results unmatched", len(AllExpected), OrigExpectedLen)
	}

	//there was no data present, just dump
	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
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
	if failure {
		expectedResultsFile = expectedResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedResultsFile)
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
		log.Printf("done")
		os.Exit(1)
	}
	log.Infof("parser tests are finished.")

	if r, err := testBucketsOutput(target_dir, bucketsOutput); !r {
		log.Fatalf("Buckets error: %s", err)
	}

	close(outputEventChan)

	log.Printf("Waiting for bucket tomb to die")
	if err := potomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	log.Printf("Testing postoverflows")

	checkResultPo(target_dir, testsFailed == 0)
	log.Infof("tests are finished.")

	return true, nil
}

type Flags struct {
	ConfigFile string
	TargetDir  string
}

func (f *Flags) Parse() {
	flag.StringVar(&f.ConfigFile, "config", "./dev.yaml", "configuration file")
	flag.StringVar(&f.TargetDir, "target", "", "target test dir")

	flag.Parse()
}

func main() {
	var (
		err     error
		cConfig *csconfig.GlobalConfig
		flags   *Flags
		files   []string
	)
	log.SetLevel(log.InfoLevel)

	log.Infof("built against %s", cwversion.VersionStr())
	flags = &Flags{}
	flags.Parse()

	if flags.TargetDir == "" {
		log.Fatalf("A target test directory is required (-target)")
	}

	cConfig = csconfig.NewConfig()
	err = cConfig.LoadConfigurationFile(flags.ConfigFile)
	if err != nil {
		log.Fatalf("Failed to load configuration : %s", err)
	}

	// ugly way of overwriting local acquis.yaml configuration
	cConfig.Crowdsec.AcquisitionFilePath = flags.TargetDir + "/acquis.yaml"
	err = cConfig.LoadConfiguration()
	if err != nil {
		log.Fatalf("Failed to load configuration : %s", err)
	}

	err = exprhelpers.Init()
	if err != nil {
		log.Fatalf("Failed to init expr helpers : %s", err)
	}

	// Start loading configs
	if err := cwhub.GetHubIdx(cConfig.Cscli); err != nil {
		log.Fatalf("Failed to load hub index : %s", err)
	}

	csParsers := newParsers()
	if csParsers, err = parser.LoadParsers(cConfig, csParsers); err != nil {
		log.Fatalf("Failed to load parsers: %s", err)
	}

	for _, hubScenarioItem := range cwhub.GetItemMap(cwhub.SCENARIOS) {
		if hubScenarioItem.Installed {
			files = append(files, hubScenarioItem.LocalPath)
		}
	}

	log.Infof("Loading %d scenario files", len(files))

	buckets = leaky.NewBuckets()
	holders, outputEventChan, err = leaky.LoadBuckets(cConfig.Crowdsec, files)

	testOneDir(flags.TargetDir, csParsers, cConfig)

}
