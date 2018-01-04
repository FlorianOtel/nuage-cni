package main

import (
	"fmt"
	"log"

	"github.com/OpenPlatformSDN/nuage-cni/agent/server"

	"github.com/OpenPlatformSDN/nuage-cni/config"

	"flag"
	"os"
	"path"

	"github.com/golang/glog"
)

const (
	errorLogLevel = 2
)

func main() {

	Config := new(config.Config)

	Flags(Config, flag.CommandLine)
	flag.Parse()

	if len(os.Args) == 1 { // With no arguments, print default usage
		flag.PrintDefaults()
		os.Exit(0)
	}
	// Flush the logs upon exit
	defer glog.Flush()

	glog.Infof("===> Starting %s...", path.Base(os.Args[0]))

	if err := config.LoadConfig(Config); err != nil {
		glog.Fatalf("Cannot read configuration file: %s", err)

	}

	if err := server.Server(Config); err != nil {
		glog.Fatalf("Failed to start agent server: %s", err)
	}
}

////////
////////
////////

func Flags(conf *config.Config, flagSet *flag.FlagSet) {
	flagSet.StringVar(&conf.ConfigFile, "config",
		"/opt/nuage/etc/nuage-cni-config.yaml", "Nuage CNI agent server configuration file. If this file is specified, remaining arguments will be ignored")

	flagSet.StringVar(&conf.AgentConfig.ServerPort, "serverport",
		"7443", "Nuage CNI agent server port")

	flagSet.StringVar(&conf.AgentConfig.CaFile, "cafile",
		"/opt/nuage/etc/ca.crt", "Nuage CNI agent server CA certificate")

	flagSet.StringVar(&conf.AgentConfig.CertCaFile, "certcafile",
		"/opt/nuage/etc/agent-server.pem", "Nuage CNI agent server certificate (server + CA certificates PEM file)")

	flagSet.StringVar(&conf.AgentConfig.KeyFile, "keyfile",
		"/opt/nuage/etc/agent-server.key", "Nuage CNI agent server private key file")
	// Set the values for log_dir and logtostderr.  Because this happens before flag.Parse(), cli arguments will override these.
	// Also set the DefValue parameter so -help shows the new defaults.
	// XXX - Make sure "glog" package is imported at this point, otherwise this will panic
	log_dir := flagSet.Lookup("log_dir")
	log_dir.Value.Set(fmt.Sprintf("/var/log/%s", path.Base(os.Args[0])))
	log_dir.DefValue = fmt.Sprintf("/var/log/%s", path.Base(os.Args[0]))
	logtostderr := flagSet.Lookup("logtostderr")
	logtostderr.Value.Set("false")
	logtostderr.DefValue = "false"
	stderrlogthreshold := flagSet.Lookup("stderrthreshold")
	stderrlogthreshold.Value.Set("2")
	stderrlogthreshold.DefValue = "2"
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

/*

func Flags(conf *config.Config, flagSet *flag.FlagSet) {
	// Reminder
	// agentname := "agent"
	//
	flagSet.StringVar(&conf.ConfigFile, "config",
		"/opt/nuage/etc/nuage-cni-config.yaml", "Nuage CNI agent and client:  Configuration file. If this file is specified, remaining arguments (except 'orchestrator' for client)  will be ignored")

	flagSet.StringVar(&conf.Orchestrator, "orchestrator",
		"Kubernetes", "Nuage client: Container orchestrator. This must be non-empty")

	flagSet.StringVar(&conf.VrsConfig.Endpoint, "vrsendpoint",
		"/var/run/openvswitch/db.sock", "Nuage CNI client: VRS UNIX socket file")

	flagSet.StringVar(&conf.VrsConfig.Bridge, "vrsbridge",
		"alubr0", "Nuage CNI client: VRS bridge name")

	flagSet.StringVar(&conf.AgentConfig.ServerPort, "serverport",
		"7443", "Nuage CNI agent and client: Agent server port")

	flagSet.StringVar(&conf.AgentConfig.CaFile, "cafile",
		"/opt/nuage/etc/ca.crt", "Nuage CNI agent and client: Agent server CA certificate")

	flagSet.StringVar(&conf.AgentConfig.CertCaFile, "certcafile",
		"/opt/nuage/etc/agent-server.pem", "Nuage CNI agent and client: Agent server certificate (server + CA certificates PEM file)")

	flagSet.StringVar(&conf.AgentConfig.KeyFile, "keyfile",
		"/opt/nuage/etc/agent-server.key", "Nuage CNI agent and client: Agent server private key file")
	// Set the values for log_dir and logtostderr.  Because this happens before flag.Parse(), cli arguments will override these.
	// Also set the DefValue parameter so -help shows the new defaults.
	// XXX - Make sure "glog" package is imported at this point, otherwise this will panic
	log_dir := flagSet.Lookup("log_dir")
	log_dir.Value.Set(fmt.Sprintf("/var/log/%s", path.Base(os.Args[0])))
	log_dir.DefValue = fmt.Sprintf("/var/log/%s", path.Base(os.Args[0]))
	logtostderr := flagSet.Lookup("logtostderr")
	logtostderr.Value.Set("false")
	logtostderr.DefValue = "false"
	stderrlogthreshold := flagSet.Lookup("stderrthreshold")
	stderrlogthreshold.Value.Set("2")
	stderrlogthreshold.DefValue = "2"
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

*/
