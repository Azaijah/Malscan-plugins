package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pclamav/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "clamav"
	category = "av"
)

// Path to file
var (
	path string
)

// ResultsData - holds scan results
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Known    string `json:"known" structs:"known"`
	Updated  string `json:"updated" structs:"updated"`
	Error    string `json:"error" structs:"error"`
}

// ClamAV - holds full set of results
type ClamAV struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// AvScan - Responsible for performing anti-virus scan and returning parsed output
func AvScan(timeout int) ClamAV {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	results, err := utils.RunCommand(ctx, "/usr/bin/clamscan", "--stdout", path)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error running scan command"))
	}

	return ClamAV{
		Results: ParseClamAvOutput(results, err),
	}
}

// ParseClamAvOutput - Responsible for parsing clamav cmd output
func ParseClamAvOutput(clamout string, err error) ResultsData {

	clamavResults := ResultsData{
		Infected: false,
		Updated:  getUpdatedDate(),
		Error:    "nil",
	}

	if err != nil && err.Error() != "exit status 1" {
		clamavResults.Error = err.Error()
		return clamavResults
	}

	lines := strings.Split(clamout, "\n")
	// Extract AV Scan Result
	result := lines[0]
	if len(result) != 0 {
		pathAndResult := strings.Split(result, ":")
		if strings.Contains(pathAndResult[1], "OK") {
			clamavResults.Infected = false
		} else {
			clamavResults.Infected = true
			clamavResults.Result = strings.TrimSpace(strings.TrimRight(pathAndResult[1], "FOUND"))
		}
	}
	// Extract Clam Details from SCAN SUMMARY
	for _, line := range lines[1:] {
		if len(line) != 0 {
			keyvalue := strings.Split(line, ":")
			if len(keyvalue) != 0 {
				switch {
				case strings.Contains(keyvalue[0], "Known viruses"):
					clamavResults.Known = strings.TrimSpace(keyvalue[1])
				case strings.Contains(line, "Engine version"):
					clamavResults.Engine = strings.TrimSpace(keyvalue[1])
				}
			}
		}
	}

	return clamavResults
}

//updateAV - Responsible for updating clamav signatures
func updateAV(ctx context.Context) error {
	out, err := utils.RunCommand(ctx, "freshclam")
	if err != nil {
		fmt.Println(1)
		log.Debug(errors.Wrap(err, "Error running update command"))
		return err
	}

	if strings.Contains(out, "Database updated") || strings.Contains(out, "daily.cld is up to date") {
		fmt.Println(0)
	} else {
		fmt.Println(1)
	}

	t := time.Now().Format("20060102")
	err = ioutil.WriteFile("/var/log/malscan/updated.log", []byte(t), 0644)
	return err
}

//getUpdatedDate - Responsible for finding when clamav signatures were last updated
func getUpdatedDate() string {

	if _, err := os.Stat("/var/log/malscan/updated.log"); os.IsNotExist(err) {
		return ""
	}

	updated, err := ioutil.ReadFile("/var/log/malscan/updated.log")
	if err != nil {
		log.Debug(errors.Wrap(err, "Error reading updated.log"))
		updated = []byte("updated error")
	}

	return string(updated)
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "clamav"
	app.Usage = "Malscan clamav plugin"
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
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) error {
				ctx, cancel := context.WithTimeout(
					context.Background(),
					time.Duration(c.GlobalInt("timeout"))*time.Second,
				)
				defer cancel()

				return updateAV(ctx)
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, _ = filepath.Abs(c.Args().First())

			clamav := AvScan(c.Int("timeout"))

			//Convert clamav results to json
			clamavJSON, _ := json.Marshal(clamav)

			//Print json results
			fmt.Println(string(clamavJSON))

		}
		return nil
	}

	app.Run(os.Args)
}
