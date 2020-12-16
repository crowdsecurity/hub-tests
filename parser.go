package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func (tp *TestParsers) LoadResults() error {
	var (
		err error
	)
	tp.ExpectedPresent = false
	tp.ParserResult = &ParserResults{}

	log.Debugf("looking for test results in %s", tp.ResultFile)
	_, err = ioutil.ReadFile(tp.ResultFile)

	if err != nil {
		log.Warningf("no result in %s, will dump data instead!", tp.ResultFile)
	} else {
		err = retrieveAndUnmarshal(tp.ResultFile, tp.ParserResult)
		if err == nil {
			tp.ExpectedPresent = true
		} else {
			return errors.Wrapf(err, "Unable to unmarsharl %s", tp.ResultFile)
		}
		//there was no data present, just dump
	}
	return nil

}

func (tp *TestParsers) CheckAndStoreResults(results ParserResults) error {
	var (
		err, err2 error
	)
	if !tp.ExpectedPresent {
		log.Warningf("result file missing dump and bailing out")
		if err = marshalAndStore(results, tp.ResultFile); err != nil {
			log.Fatalf("unable to marshal and store %s", tp.ResultFile)
		}
		return errors.New(fmt.Sprintf("result file %s missing dump", tp.ResultFile))
	}

	//First check the Final results
	//TODO avoid having TestResults writing its own failure file. For now we let it write it, and we overfwrite
	if err = TestResults(tp.ParserResult.FinalResults, results.FinalResults, tp.ResultFile+".fail", tp.current, false); err != nil {
		//final result is not validated bailing output
		if err2 = marshalAndStore(results, tp.ResultFile+".fail"); err2 != nil {
			log.Fatalf("unable to marshal and store %s", tp.ResultFile)
		}
		return err
	}

	//second check the provisional results
	if err = TestProvisionalResults(tp.ParserResult.ProvisionalResults, results.ProvisionalResults, tp.ResultFile+".fail", tp.current); err != nil {
		//provisional result is not validated bailing output
		return err
	}

	return nil
}

func addFakeNodes(ctx *parser.UnixParserCtx, nodes []parser.Node, parserDir string) (*parser.UnixParserCtx, []parser.Node) {
	var (
		err    error
		dirs   []os.FileInfo
		stages []string = []string{}
	)

	if dirs, err = ioutil.ReadDir(parserDir); err != nil {
		log.Fatalf("unable to read ./parsers directory: %s", err)
	}

	for _, dir := range dirs {
		if dir.IsDir() {
			stages = append(stages, dir.Name())
		}
	}

	log.Tracef("Detected stages: %+v", stages)
	existing_stages := map[string]bool{}
	for _, node := range nodes {
		existing_stages[node.Stage] = true
	}
	for _, stage := range stages {
		if _, ok := existing_stages[stage]; !ok {
			log.Tracef("adding fake node for stage %s", stage)
			nodes = append(nodes, createFakeNode(stage))
		}
	}

	ctx.Stages = stages
	return ctx, nodes
}

func createFakeNode(stage string) parser.Node {
	return parser.Node{
		Stage:     stage,
		Logger:    log.NewEntry(log.StandardLogger()),
		OnSuccess: "next_stage",
	}
}

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

func (tp *TestParsers) Parse(parsers *parser.Parsers, events []types.Event) error {
	var (
		err     error
		results ParserResults = ParserResults{
			FinalResults:       make([]types.Event, 0),
			ProvisionalResults: make([]map[string]map[string]types.Event, 0),
		}
		parsed        types.Event
		unparsedLines int = 0
		readLines     int = 0
	)
	//load parsers
	log.Infof("Loading parsers")
	//load the expected results

	if tp.current == "parsers" {
		tp.ResultFile = tp.LocalConfig.targetDir + "/" + tp.LocalConfig.ParserResultFile
	}

	if tp.current == "postoverflows" {
		tp.ResultFile = tp.LocalConfig.targetDir + "/" + tp.LocalConfig.PoResultFile
	}

	if err = tp.LoadResults(); err != nil {
		log.Fatalf("error unmarshalling %s: %s", tp.ResultFile, err)
	}
	parser.ParseDump = true
	results.FinalResults = make([]types.Event, 0)

	for _, event := range events {
		switch tp.current {
		case "parsers":
			parsed, err = parser.Parse(*parsers.Ctx, event, parsers.Nodes) //add a switch for postoverflow here
		case "postoverflows":
			parsed, err = parser.Parse(*parsers.Povfwctx, event, parsers.Povfwnodes) //add a switch for postoverflow here
		default:
			log.Fatalf("don't know what to do, test parsers or postoverflows ?")
		}

		if err != nil {
			log.Fatalf("parsing error: %s", err) //useless: parser.Parse truly never return err != nil
		}

		if !parsed.Process {
			unparsedLines++
			log.Errorf("unparsed line: %s", event.Line.Raw)
		}

		readLines++
		results.FinalResults = append(results.FinalResults, cleanForMatchEvent(parsed))
		results.ProvisionalResults = append(results.ProvisionalResults, cleanForMatch(parser.StageParseCache))
		log.Printf("one line done")
	}

	//parser result analysis
	log.Infof("%d/%d lines parsed successfully, %d UNPARSED", readLines-unparsedLines, readLines, unparsedLines)

	// in case all lines are not parsed, bail out
	if readLines == unparsedLines {
		return errors.New("No line was successfully parsed")
	}
	if err = tp.CheckAndStoreResults(results); err != nil {
		log.Errorf("Diff error: %s", err)
	}
	return err
}
