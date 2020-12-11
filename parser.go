package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"sync"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

// Return new parsers
// nodes and povfwnodes are already initialized in parser.LoadStages
func newParsers(index map[string]map[string]cwhub.Item, local ConfigTest) *parser.Parsers {
	parsers := &parser.Parsers{
		Ctx:             &parser.UnixParserCtx{},
		Povfwctx:        &parser.UnixParserCtx{},
		StageFiles:      make([]parser.Stagefile, 0),
		PovfwStageFiles: make([]parser.Stagefile, 0),
	}
	for _, itemType := range []string{cwhub.PARSERS, cwhub.PARSERS_OVFLW} {
		for _, hubParserName := range local.Configurations[itemType] {
			hubParserItem := index[itemType][hubParserName]
			hubParserItem.LocalPath = hubParserItem.RemotePath

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

			if err := getDataFromFile(hubParserItem.LocalPath, "./data"); err != nil { //TODO have a way to fix this hardcoded direcotry
				log.Errorf("Unable to get data for %s", hubParserItem.LocalPath)
			}
		}
	}

	sort.Slice(parsers.StageFiles, func(i, j int) bool {
		return parsers.StageFiles[i].Filename < parsers.StageFiles[j].Filename
	})
	sort.Slice(parsers.PovfwStageFiles, func(i, j int) bool {
		return parsers.PovfwStageFiles[i].Filename < parsers.PovfwStageFiles[j].Filename
	})
	return parsers
}

//ret : test_ok, parsed_ok, error
func parseMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (bool, bool, types.Event, error) {
	var (
		err    error
		parsed types.Event
	)
	oneResult := LineParseResult{}
	h := sha256.New()

	h.Write([]byte(event.Line.Raw))
	//parse
	parsed, err = parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		return false, false, types.Event{}, fmt.Errorf("failed parsing : %v\n", err) //parser.Parse truly never return err != nil
	}

	if !parsed.Process {
		return true, false, types.Event{}, fmt.Errorf("unparsed line %s", parsed.Line.Raw)
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
			return false, true, types.Event{}, fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(candidate, oneResult, opt))
		}
		break
	}
	if !matched && len(AllExpected) != 0 {
		return false, true, types.Event{}, fmt.Errorf("Result is not in the %d expected results", len(AllExpected))
	}
	return matched, true, parsed, nil
}

func testParser(parsers *parser.Parsers, localConfig ConfigTest) error {
	var (
		err error
		//		acquisitionCTX  *acquisition.FileAcquisCtx
		inputLineChan   = make(chan types.Event)
		failure         bool
		OrigExpectedLen int
		dataSrc         []acquisition.DataSource
		acquisTomb      tomb.Tomb
		ptomb           tomb.Tomb
		bucketsInput    []types.Event = []types.Event{}
	)
	AllResults = make([]LineParseResult, 0)
	AllExpected = make([]LineParseResult, 0)

	if localConfig.ParserInputFile == "" {
		fakeCrowdsecServicecfg := csconfig.GlobalConfig{
			ConfigPaths: &csconfig.ConfigurationPaths{
				ConfigDir: "./config",
				DataDir:   "./data/",
			},
			Crowdsec: &csconfig.CrowdsecServiceCfg{
				AcquisitionFilePath: localConfig.target_dir + "/acquis.yaml",
			},
		}
		log.Infof("Loading acquisition")

		dataSrc, err = acquisition.LoadAcquisitionFromFile(fakeCrowdsecServicecfg.Crowdsec)
		if err != nil {
			errors.Wrap(err, "Not able to init acquisition")
		}
		for _, filectx := range dataSrc {
			if filectx.Mode() != "cat" {
				log.Warning("The mode of reading the log file is not 'cat'. The whole thing is highly probably bound to fail")
			}
		}
	}

	//load parsers
	log.Infof("Loading parsers")
	//load the expected results
	ExpectedPresent := false
	expectedResultsFile := localConfig.target_dir + "/" + localConfig.ParserResultFile
	expected_bytes, err := ioutil.ReadFile(expectedResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", localConfig.target_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllExpected); err != nil {
			return fmt.Errorf("file %s can't be unmarshaled : %s", expectedResultsFile, err)
		} else {
			ExpectedPresent = true
			OrigExpectedLen = len(AllExpected)
		}
	}

	linesRead := 0
	linesUnparsed := 0

	parser.ParseDump = true
	ptomb = tomb.Tomb{}
	acquisTomb = tomb.Tomb{}

	ptomb.Go(func() error {
		log.Printf("Processing logs")
		for {
			select {
			case event, ok := <-inputLineChan:
				if !ok {
					return nil
				}
				log.Debugf("about to add one line")
				linesRead++
				test_ok, parsed_ok, parsed, err := parseMatchLine(event, parsers.Ctx, parsers.Nodes)
				bucketsInput = append(bucketsInput, parsed)
				log.Printf("one line done")
				if !parsed_ok {
					if err != nil {
						log.Errorf("parser error : %s", err)
					}
					linesUnparsed++
				}
				if !test_ok {
					failure = true
					// TODO: estsFailed++
					log.Errorf("test %d failed", linesRead)
					if err != nil {
						log.Errorf("test failure: %s", err)
					}
				}
			case <-ptomb.Dying():
				return nil
			}
		}
	})
	wg := sync.WaitGroup{}
	wg.Add(1)
	if localConfig.ParserInputFile == "" {
		go acquisition.StartAcquisition(dataSrc, inputLineChan, &acquisTomb)
		log.Printf("waiting for acquis tomb to die")
		if err := acquisTomb.Wait(); err != nil {
			return errors.Wrap(err, "acquisition returned error : %s")
		}
		log.Printf("acquis tomb died")
		wg.Done()

	} else {
		parserInput := make([]types.Event, 0)
		if err := retrieveAndUnmarshal(localConfig.target_dir+"/"+localConfig.ParserInputFile, &parserInput); err != nil {
			return errors.Wrap(err, "Couldn't load serialized parser input")
		}
		go func() {
			for _, event := range parserInput {
				inputLineChan <- event
			}
			wg.Done()
		}()
	}

	//We close the log chan, and waiting the tomb to die, to be sure not to forget event in the cloud
	wg.Wait()
	close(inputLineChan)

	log.Printf("Waiting for parsers tomb to die")
	if err := ptomb.Wait(); err != nil {
		return errors.Wrap(err, "acquisition returned error : %s")
	}

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

	if linesRead == linesUnparsed {
		return errors.New("No line was successfully parsed")
	}

	//there was no data present, just dump
	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			return errors.Wrap(err, "failed to marshal results")
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			return errors.Wrapf(err, "failed to dump data to %s", expectedResultsFile)
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
		return errors.New("Parsers test failed, bailing out")
	}
	log.Infof("parser tests are finished.")

	if err := marshalAndStore(bucketsInput, localConfig.target_dir+"/"+localConfig.BucketInputFile); err != nil {
		return errors.Wrap(err, "marshaling failed")
	}
	return nil
}
