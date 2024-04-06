package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LiamHellend/malscan-plugin-manalyze/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "manalyze"
	category = "enricher"
)

var (
	path string
)

// Manalyze json object (this is what gets output)
type Manalyze struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// ResultsData json object
type ResultsData struct {
	Architecture      string
	CompilationDate   string
	DetectedLanguages string
	FileVersion       string
	InternalName      string
	OriginalFilename  string
	ProductName       string
	ProductVersion    string
	Subsystem         string
	Sections          []string
	Imports           map[string][]string
	Error             string `json:"error" structs:"error"`
}

// AvScan performs antivirus scan
func AvScan(timeout int) Manalyze {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	results, err := utils.RunCommand(ctx, "/opt/Manalyze/bin/manalyze", "--output=json", "--dump=summary,sections,imports", path)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while running manalyze command"))
	}

	return Manalyze{
		Results: ParseOutput([]byte(results), err),
	}
}

// ParseOutput converts manalyze output into a manalyze struct
func ParseOutput(manalyzeout []byte, err error) ResultsData {

	manalyzeResult := ResultsData{Error: "nil"}

	if err != nil {
		manalyzeResult.Error = err.Error()
		return manalyzeResult
	}

	var summary map[string]map[string]map[string]string
	var sections map[string]map[string]map[string]interface{}
	var imports map[string]map[string]map[string][]string

	err = json.Unmarshal(manalyzeout, &summary)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while unmarshaling summary manalyze output"))
	}
	err = json.Unmarshal(manalyzeout, &sections)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while unmarshaling sections manalyze output"))
	}
	err = json.Unmarshal(manalyzeout, &imports)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while unmarshaling imports manalyze output"))
	}

	manalyzeResult.Architecture = summary[path]["Summary"]["Architecture"]
	manalyzeResult.CompilationDate = summary[path]["Summary"]["Compilation Date"]
	manalyzeResult.DetectedLanguages = summary[path]["Summary"]["Detected languages"]
	manalyzeResult.FileVersion = summary[path]["Summary"]["FileVersion"]
	manalyzeResult.InternalName = summary[path]["Summary"]["InternalName"]
	manalyzeResult.OriginalFilename = summary[path]["Summary"]["OriginalFilename"]
	manalyzeResult.ProductName = summary[path]["Summary"]["ProductName"]
	manalyzeResult.ProductVersion = summary[path]["Summary"]["ProductVersion"]
	manalyzeResult.Subsystem = summary[path]["Summary"]["Subsystem"]

	for k := range sections[path]["Sections"] {

		manalyzeResult.Sections = append(manalyzeResult.Sections, k)
	}

	for k, v := range imports[path]["Imports"] {
		log.Debug(k, v)
		temp := make(map[string][]string)
		temp[k] = v
		manalyzeResult.Imports = temp
	}

	return manalyzeResult
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "Manalyze"
	app.Usage = "Malscan manalyze plugin"
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "debug output",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  900,
			Usage:  "malcan plugin timeout (in seconds)",
			EnvVar: "MALSCAN_TIMEOUT",
		},
	}
	app.Action = func(c *cli.Context) error {

		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {

			path, _ = filepath.Abs(c.Args().First())

			manalyze := AvScan(c.Int("timeout"))

			// convert to JSON
			manalyzeJSON, _ := json.Marshal(manalyze)

			fmt.Println(string(manalyzeJSON))

		}

		return nil
	}

	app.Run(os.Args)

}
