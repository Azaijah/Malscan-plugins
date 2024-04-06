package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"pyara/utils"

	yara "github.com/hillu/go-yara/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "yara"
	category = "av"
	rulesDir = "/go/src/github.com/LiamHellend/malscan-plugin-yara/rules/using/testsav"
)

var (
	path         string
	yaraCompiler *yara.Compiler
)

// Yara json object
type Yara struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Matches  yara.MatchRules
}

func scan(path string, rulesDir string, timeout int) Yara {

	yaraResults := ResultsData{Infected: false}

	rules, err := yara.LoadRules(rulesDir)

	if err != nil {
		log.Debug(errors.Wrap(err, "failed to get rules"))
		return Yara{Results: yaraResults}
	}

	var scan yara.MatchRules

	err = rules.ScanFile(
		path,                               // filename string
		0,                                  // flags ScanFlags
		time.Duration(timeout)*time.Second, //timeout time.Duration
		&scan,
	)

	if err != nil {
		log.Debug(errors.Wrapf(err, "failed to scan file: %s", path))
		return Yara{Results: yaraResults}
	}

	yaraResults.Matches = scan

	if len(scan) != 0 {
		yaraResults.Infected = true
		yaraResults.Result = scan[0].Rule
	}

	return Yara{Results: yaraResults}

}

//
func update(ctx context.Context) {

}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = name
	app.Usage = "Malscan Yara AntiVirus Plugin"
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "debug output",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  300,
			Usage:  "Malscan plugin timeout (in seconds)",
			EnvVar: "MALSCAN_TIMEOUT",
		},
	}
	/*app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update rules",
			Action: func(c *cli.Context) error {
				ctx, cancel := context.WithTimeout(
					context.Background(),
					time.Duration(c.GlobalInt("timeout"))*time.Second,
				)
				defer cancel()

				return update(ctx)
			},
		},
	}*/
	app.Action = func(c *cli.Context) error {

		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, _ = filepath.Abs(c.Args().First())

			yara := scan(path, rulesDir, c.Int("timeout"))

			// convert to JSON
			yaraJSON, _ := json.Marshal(yara)

			fmt.Println(string(yaraJSON))

		}
		return nil
	}

	app.Run(os.Args)

}
