// From heartbleed.fillip.io
// Adding DynamoDB caching.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	mzutil "github.com/mozilla-services/Heartbleed/mzutil"

	flags "github.com/jessevdk/go-flags"
	bleed "github.com/mozilla-services/Heartbleed/bleed"
	cache "github.com/mozilla-services/Heartbleed/cache"
)

var (
	PAYLOAD   = []byte("heartbleed.mozilla.com")
	REDIRHOST = "http://localhost"
	PORT_SRV  = ":8082"
	/* Command line args for the app.
	 */
	opts struct {
		ConfigFile string `short:"c" long:"config" optional:"true" description:"General Config file"`
		Profile    string `long:"profile" optional:"true"`
		MemProfile string `long:"memprofile" optional:"true"`
		LogLevel   int    `short:"l" long:"loglevel" optional:"true"`
	}
	metrics *mzutil.Metrics
)

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, REDIRHOST, http.StatusFound)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "OK")
}

type result struct {
	Code  int    `json:"code"`
	Data  string `json:"data"`
	Error string `json:"error"`
	Host  string `json:"host"`
}

func handleRequest(tgt *bleed.Target, w http.ResponseWriter, r *http.Request, skip bool) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Caching
	var rc int
	var err error
	var errS string
	var metricName = []string{"vulnerable", "safe", "error"}
	data := ""
	if cReply, ok := cache.Check(tgt.HostIp); !ok {

		log.Printf("Checking " + tgt.HostIp)
		data, err = bleed.Heartbleed(tgt, PAYLOAD, skip)

		if err == bleed.Safe || err == bleed.Closed {
			rc = 1
		} else if err != nil {
			rc = 2
		} else {
			rc = 0
			// _, err := bleed.Heartbleed(tgt, PAYLOAD)
			// if err == nil {
			// 	// Two VULN in a row
			// 	rc = 0
			// } else {
			// 	// One VULN and one not
			// 	_, err := bleed.Heartbleed(tgt, PAYLOAD)
			// 	if err == nil {
			// 		// 2 VULN on 3 tries
			// 		rc = 0
			// 	} else {
			// 		// 1 VULN on 3 tries
			// 		if err == bleed.Safe {
			// 			rc = 1
			// 		} else {
			// 			rc = 2
			// 		}
			// 	}
			// }
		}
		metrics.Increment("total")
		metrics.Increment(metricName[rc])

		cerr := cache.Set(tgt.HostIp, rc)
		if cerr != nil {
			log.Printf("Cache Error!: %s", err.Error())
		}

		switch rc {
		case 0:
			log.Printf("%v (%v) - VULNERABLE [skip: %v]", tgt.HostIp, tgt.Service, skip)
		case 1:
			data = ""
			log.Printf("%v (%v) - SAFE", tgt.HostIp, tgt.Service)
		case 2:
			data = ""
			if err != nil {
				errS = err.Error()
				if errS == "Please try again" {
					log.Printf("%v (%v) - MISMATCH", tgt.HostIp, tgt.Service)
				} else {
					log.Printf("%v (%v) - ERROR [%v]", tgt.HostIp, tgt.Service, errS)
				}
			}
		}
	} else {
		metrics.Increment("cached")
		rc = int(cReply.Status)
	}

	// clear the data, because we don't want to expose that.
	data = ""

	res := result{rc, data, errS, tgt.HostIp}
	j, err := json.Marshal(res)
	if err != nil {
		log.Println("ERROR", err)
	} else {
		w.Write(j)
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	snapshot := metrics.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	reply, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("ERROR: Could not generate metrics report: " + err.Error())
		w.Write([]byte("{}"))
		return
	} else {
		if reply == nil {
			reply = []byte("{}")
		}
	}
	w.Write(reply)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func bleedHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Path[len("/bleed/"):]

	tgt := bleed.Target{
		HostIp:  string(host),
		Service: "https",
	}
	handleRequest(&tgt, w, r, true)
}

func bleedQueryHandler(w http.ResponseWriter, r *http.Request) {
	q, ok := r.URL.Query()["u"]
	if !ok || len(q) != 1 {
		return
	}

	skip, ok := r.URL.Query()["skip"]
	s := false
	if ok && len(skip) == 1 {
		s = true
	}

	tgt := bleed.Target{
		HostIp:  string(q[0]),
		Service: "https",
	}

	u, err := url.Parse(tgt.HostIp)
	if err == nil && u.Host != "" {
		tgt.HostIp = u.Host
		if u.Scheme != "" {
			tgt.Service = u.Scheme
		}
	}

	handleRequest(&tgt, w, r, s)
}

func main() {

	var err error

	// Get the configurations
	flags.Parse(&opts)
	if opts.ConfigFile == "" {
		opts.ConfigFile = "config.ini"
	}
	config, err := mzutil.ReadMzConfig(opts.ConfigFile)
	if err != nil {
		log.Fatal("Could not read config file " +
			opts.ConfigFile + " " +
			err.Error())
	}
	config.SetDefault("VERSION", "0.5")
	REDIRHOST = config.Get("redir.host", "localhost")
	PORT_SRV = config.Get("listen.port", ":8082")
	cache.Init(config.Get("godynamo.conf.file", "./conf/aws-config.json"),
		config.Get("expry", "10m"))
	metrics = mzutil.NewMetrics("heartbleed", config)

	// should take a conf arg

	http.HandleFunc("/", defaultHandler)
	// Required for some ELBs
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/metrics", metricsHandler)
	http.HandleFunc("/bleed/", bleedHandler)
	http.HandleFunc("/bleed/query", bleedQueryHandler)
	log.Printf("Starting server on %s\n", PORT_SRV)
	err = http.ListenAndServe(PORT_SRV, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
