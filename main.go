package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"flag"
	"os"
	"reflect"
	"time"
	"sort"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var (
	acquisTomb tomb.Tomb
	testDir string
	
	AllResults []LineParseResult
	AllExpected []LineParseResult
	
	holders         []leaky.BucketFactory
	buckets         *leaky.Buckets

	outputEventChan chan types.Event

)

type LineParseResult struct {
	Line          string
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

//ret : test_ok, parsed_ok, error
func parseMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (bool, bool, error) {
	var (
		err error
		parsed types.Event
		
	)
	oneResult := LineParseResult{}
	h := sha256.New()

	if event.Line.Raw == "" {
		log.Warningf("discarding empty line")
		return true, false, nil
	}
	h.Write([]byte(event.Line.Raw))
	//parse
	parsed, err = parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		return false, false, fmt.Errorf("failed parsing : %v\n", err)
	}

	// if (parsed.Overflow.BucketId == "") || parsed.Overflow.Reprocess {
	// 	log.Infof("Pouring buckets")
	// 	_, err = leaky.PourItemToHolders(parsed, holders, buckets)
	// }
	// if err != nil {
	// 	log.Fatalf("bucketify failed for: %v", parsed)
	// }

	if !parsed.Process {
		return true, false, fmt.Errorf("unparsed line %s", parsed.Line.Raw)
	}
	
	//marshal current result
	oneResult.Line = parsed.Line.Raw
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)

	opt := getCmpOptions()
	/*
		Iterate over the list of expected results and try to find back
	*/
	AllResults = append(AllResults, oneResult)
	matched := false
	for idx, candidate := range AllExpected {
		//not our line
		if candidate.Line != event.Line.Raw {			
			continue
		}
		if cmp.Equal(candidate, oneResult, opt) {
			matched = true
			//we go an exact match
			AllExpected = append(AllExpected[:idx], AllExpected[idx+1:]...)
		} else {
			return false, true, fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(candidate, oneResult, opt))
		}
		break
	}
	if !matched && len(AllExpected) != 0 {
		return false, true, fmt.Errorf("Result is not in the %d expected results", len(AllExpected))
	}
	return matched, true, nil
}

func testBucketsOutput(target_dir string) (bool, error) {
	var (
		OrigExpectedLen int

		AllBucketsResult []types.Event = []types.Event{}
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

	opt := getCmpOptions()
	matched := false
	if cmp.Equal(AllBucketsExpected, AllBucketsResult, opt) {
		matched = true
	} else {
		return true, fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(AllBucketsExpected, AllBucketsResult, opt))
	}

	if !matched && len(AllExpected) != 0 {
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
		return false, fmt.Errorf("Result is not in the %d expected results", len(AllExpected))
	
	}
	log.Infof("%d/%d matched results", OrigExpectedLen-len(AllBucketsExpected), OrigExpectedLen)
	log.Infof("tests are finished.")
	return true, nil

}

func testOneDir(target_dir string, parsers *parser.Parsers, cConfig *csconfig.GlobalConfig) (bool, error) {
	var (
		err error
		acquisitionCTX *acquisition.FileAcquisCtx
		inputLineChan = make(chan types.Event)
		failure bool
		OrigExpectedLen int
		tmpctx []acquisition.FileCtx
		ptomb, potomb tomb.Tomb
		bucketsOutput []types.Event		
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
	ptomb.Go(func() error {
		
		//log.Printf("Processing lines")
		log.Printf("processing loop over parsing")
		for {
			select {
			case event, ok := <- inputLineChan:
				if !ok {
					return nil
				}
				log.Printf("one line")
				linesRead++
				test_ok, parsed_ok, err := parseMatchLine(event, parsers.Ctx, parsers.Nodes)
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
			case <- ptomb.Dying():
				return nil			
			}
		}
		return nil
	})

	
	bucketsOutput = []types.Event{}
	potomb.Go(func() error {
		log.Printf("processing loop over postoveflow")
		for {
			select {
			case event, ok := <- outputEventChan:
				if !ok {
					return nil
				}
				bucketsOutput = append(bucketsOutput, event)
				test_ok, parsed_ok, err := parseMatchLine(event, parsers.Povfwctx , parsers.Povfwnodes)
				if !parsed_ok {
					if err != nil {
						log.Warningf("parser error : %s", err)
					}
					linesUnparsed++
				}
				if !test_ok {
					//				failure = true
					testsFailed++
					log.Errorf("test %d failed.", linesRead)
					if err != nil {
						log.Errorf("test failure : %s", err)
					}
				}
			case <- ptomb.Dying():
				return nil
			}
			
		}
		return nil
	})

	
	log.Printf("waiting for acquis tomb to die")
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	close(inputLineChan)
	log.Printf("Waiting for parsers tomb to die")
	if err := ptomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	close(outputEventChan)
	log.Printf("Waiting for parsers tomb to die")
	if err := potomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}


	time.Sleep(1 * time.Second)
	/*now let's check the results*/

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

	// if r, err := testBucketsOutput(target_dir);!r {
	// 	log.Fatalf("Buckets error: %s", err)
	// }

	
	return true, nil
}

// Return new parsers
// nodes and povfwnodes are already initialized in parser.LoadStages
func newParsers() *parser.Parsers {
	parsers := &parser.Parsers{
		Ctx:             &parser.UnixParserCtx{},
		Povfwctx:        &parser.UnixParserCtx{},
		StageFiles:      make([]parser.Stagefile, 0),
		PovfwStageFiles: make([]parser.Stagefile, 0),
	}
	for _, itemType := range []string{cwhub.PARSERS, cwhub.PARSERS_OVFLW} {
		for _, hubParserItem := range cwhub.GetItemMap(itemType) {
			if hubParserItem.Installed {
				stagefile := parser.Stagefile{
					Filename: hubParserItem.LocalPath,
					Stage:    hubParserItem.Stage,
				}
				if itemType == cwhub.PARSERS {
					parsers.StageFiles = append(parsers.StageFiles, stagefile)
				}
				if itemType == cwhub.PARSERS_OVFLW {
					parsers.PovfwStageFiles = append(parsers.PovfwStageFiles, stagefile)
				}
			}
		}
	}
	sort.Slice(parsers.StageFiles,func(i, j int) bool {
		return parsers.StageFiles[i].Filename < parsers.StageFiles[j].Filename
	})
	sort.Slice(parsers.PovfwStageFiles,func(i, j int) bool {
		return parsers.PovfwStageFiles[i].Filename < parsers.PovfwStageFiles[j].Filename
	})
	return parsers
}

type Flags struct {
	ConfigFile     string
	TargetDir string

}

func (f *Flags) Parse() {
	flag.StringVar(&f.ConfigFile, "config", "./dev.yaml", "configuration file")
	flag.StringVar(&f.TargetDir, "target", "", "target test dir")

	flag.Parse()
}

func main() {
	var (
		err       error
		cConfig *csconfig.GlobalConfig
		flags *Flags
		files []string
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
