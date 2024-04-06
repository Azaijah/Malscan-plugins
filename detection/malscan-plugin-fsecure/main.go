package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/LiamHellend/malscan-plugin-fsecure/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "fsecure"
	category = "av"
)

var (
	path string
)

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Database string `json:"database" structs:"database"`
	Updated  string `json:"updated" structs:"updated"`
	Error    string `json:"error" structs:"error"`
}

//ScanEngines - Fsecure has two different engines
type ScanEngines struct {
	FSE      string `json:"fse" structs:"fse"`
	Aquarius string `json:"aquarius" structs:"aquarius"`
}

// FSecure json object
type FSecure struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// AvScan performs antivirus scan
func AvScan(timeout int) FSecure {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	results, err := utils.RunCommand(
		ctx,
		"/opt/f-secure/fsav/bin/fsav",
		"--virus-action1=none",
		path,
	)

	if err != nil && err.Error() != "exit status 3" {
		// If fails try a second time
		results, err = utils.RunCommand(
			ctx,
			"/opt/f-secure/fsav/bin/fsav",
			"--virus-action1=none",
			path,
		)

		if err != nil {
			log.Debug(errors.Wrap(err, "Error while runing scan command"))
		}
	}

	if err != nil {
		// FSecure exits with error status 3 if it finds a virus
		if err.Error() == "exit status 3" {
			err = nil
		}
	}

	return FSecure{Results: ParseFSecureOutput(results, err)}
}

// ParseFSecureOutput convert fsecure output into ResultsData struct
func ParseFSecureOutput(fsecureout string, err error) ResultsData {

	// root@70bc84b1553c:/malware# fsav --virus-action1=none eicar.com.txt
	// EVALUATION VERSION - FULLY FUNCTIONAL - FREE TO USE FOR 30 DAYS.
	// To purchase license, please check http://www.F-Secure.com/purchase/
	//
	// F-Secure Anti-Virus CLI version 1.0  build 0060
	//
	// Scan started at Mon Aug 22 02:43:50 2016
	// Database version: 2016-08-22_01
	//
	// eicar.com.txt: Infected: EICAR_Test_File [FSE]
	// eicar.com.txt: Infected: EICAR-Test-File (not a virus) [Aquarius]
	//
	// Scan ended at Mon Aug 22 02:43:50 2016
	// 1 file scanned
	// 1 file infected

	version, database := getFSecureVersion()

	fsecure := ResultsData{
		Infected: false,
		Engine:   version,
		Database: database,
		Updated:  getUpdatedDate(),
		Error:    "nil",
	}

	scanEng := ScanEngines{}

	if err != nil {
		fsecure.Error = err.Error()
		return fsecure
	}

	lines := strings.Split(fsecureout, "\n")

	for _, line := range lines {
		if strings.Contains(line, "Infected:") && strings.Contains(line, "[FSE]") {
			fsecure.Infected = true
			parts := strings.Split(line, "Infected:")
			scanEng.FSE = strings.TrimSpace(strings.TrimSuffix(parts[1], "[FSE]"))
			continue
		}
		if strings.Contains(line, "Infected:") && strings.Contains(line, "[Aquarius]") {
			fsecure.Infected = true
			parts := strings.Split(line, "Infected:")
			scanEng.Aquarius = strings.TrimSpace(strings.TrimSuffix(parts[1], "[Aquarius]"))
		}
	}
	fsecure.Result = strings.TrimSpace(fmt.Sprintf("%s %s", "Aquarius:"+scanEng.Aquarius, "FSE:"+scanEng.FSE))

	return fsecure
}

// getFSecureVersion get Anti-Virus scanner version
func getFSecureVersion() (version string, database string) {

	exec.Command("/opt/f-secure/fsav/bin/fsavd").Output()
	versionOut, _ := utils.RunCommand(nil, "/opt/f-secure/fsav/bin/fsav", "--version")

	return parseFSecureVersion(versionOut)
}

func parseFSecureVersion(versionOut string) (version string, database string) {

	lines := strings.Split(versionOut, "\n")

	for _, line := range lines {

		if strings.Contains(line, "F-Secure Linux Security version") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "F-Secure Linux Security version"))
		}

		if strings.Contains(line, "Database version:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				database = strings.TrimSpace(parts[1])
				break
			} else {
				log.Debug("Something went wrong... ", parts)
			}
		}

	}

	return
}

func parseUpdatedDate(date string) string {
	layout := "Mon, 02 Jan 2006 15:04:05 +0000"
	t, _ := time.Parse(layout, date)
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

func getUpdatedDate() string {
	if _, err := os.Stat("/var/log/malscan/updated.log"); os.IsNotExist(err) {
		return ""
	}
	updated, _ := ioutil.ReadFile("/var/log/malscan/updated.log")
	return string(updated)
}

func updateAV(ctx context.Context) error {

	var out string

	for i := 1; i != 3; i++ {

		cmd := exec.Command("sh", "/opt/malscan/update")
		cmdReader, err := cmd.StdoutPipe()
		scanner := bufio.NewScanner(cmdReader)
		go func() {
			for scanner.Scan() {
				out += fmt.Sprintln("\n", scanner.Text())
			}
		}()
		err = cmd.Start()
		if err != nil {
			log.Debug(errors.Wrap(err, "Error starting update command"))
			continue
		}
		err = cmd.Wait()
		if err != nil {
			log.Debug(errors.Wrap(err, "Error waiting for update command"))
			continue
		}

		break

	}

	if strings.Contains(out, "All done.") {
		fmt.Println(0)
	} else {
		fmt.Println(1)
	}

	// Update UPDATED file
	t := time.Now().Format("20060102")
	err := ioutil.WriteFile("/var/log/malscan/updated.log", []byte(t), 0644)
	return err
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "fsecure"
	app.Usage = "Malscan fsecure plugin"
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

			fsecure := AvScan(c.Int("timeout"))

			// convert to JSON
			fsecureJSON, _ := json.Marshal(fsecure)

			fmt.Println(string(fsecureJSON))

		}

		return nil
	}

	app.Run(os.Args)

}
