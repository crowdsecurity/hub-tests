package main

import (
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

func (tp *TestParsers) LaunchAcquisition() ([]types.Event, error) {
	var (
		dataSrc       []acquisition.DataSource
		output        []types.Event = []types.Event{}
		acquisTomb    *tomb.Tomb    = &tomb.Tomb{}
		err           error
		inputLineChan chan types.Event = make(chan types.Event)
		acquisMode    bool
		inputFile     string
	)

	if tp.current == "postoverflows" {
		acquisMode = false
		inputFile = tp.LocalConfig.targetDir + "/" + tp.LocalConfig.PoInputFile
		log.Infof("Currently loading postoverflow config.yaml: looking for %s", inputFile)
	}

	if tp.current == "parsers" {
		if tp.LocalConfig.ParserInputFile != "" {
			acquisMode = false
			inputFile = tp.LocalConfig.targetDir + "/" + tp.LocalConfig.ParserInputFile
			log.Infof("currently loading parser config.yaml: looking for %s", inputFile)
		} else if tp.LocalConfig.AcquisitionFile != "" {
			acquisMode = true
			log.Infof("currently loading acquis.yaml: looking for %s", tp.LocalConfig.AcquisitionFile)
		}
	}

	if acquisMode {
		var wg *sync.WaitGroup = &sync.WaitGroup{}

		fakeCrowdsecServicecfg := csconfig.Config{
			ConfigPaths: &csconfig.ConfigurationPaths{
				ConfigDir: "./config",
				DataDir:   "./data/",
			},
			Crowdsec: &csconfig.CrowdsecServiceCfg{
				AcquisitionFilePath: tp.LocalConfig.targetDir + "/" + tp.LocalConfig.AcquisitionFile,
				AcquisitionFiles:    []string{tp.LocalConfig.targetDir + "/" + tp.LocalConfig.AcquisitionFile},
			},
		}
		log.Infof("starting acquisition")

		dataSrc, err = acquisition.LoadAcquisitionFromFile(fakeCrowdsecServicecfg.Crowdsec)
		if err != nil {
			errors.Wrap(err, "not able to init acquisition")
		}
		for _, filectx := range dataSrc {
			if filectx.GetMode() != "cat" {
				log.Warning("the mode of reading the log file is not 'cat': the whole thing is doomed to fail")
			}
		}
		wg.Add(1)
		go func() {
			for event := range inputLineChan {
				output = append(output, event)
			}
			wg.Done()
		}()

		log.Printf("dataSrc: %+v", dataSrc)
		go acquisition.StartAcquisition(dataSrc, inputLineChan, acquisTomb)
		log.Printf("waiting for acquis tomb to die")

		if len(dataSrc) > 0 {
			if err := acquisTomb.Wait(); err != nil {
				return nil, errors.Wrap(err, "acquisition returned error : %s")
			}
		}
		close(inputLineChan)
		log.Printf("acquisition is finished")
		wg.Wait()

	} else {
		if err := retrieveAndUnmarshal(inputFile, &output); err != nil {
			return nil, errors.Wrapf(err, "couldn't load serialized parser input file %s", inputFile)
		}
	}
	return output, nil
}
