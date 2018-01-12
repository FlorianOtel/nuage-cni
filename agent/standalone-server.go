package main

import (
	"fmt"

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

	conf := new(config.Config)

	Flags(conf, flag.CommandLine)

	if len(os.Args) == 1 { // With no arguments, print default usage
		flag.PrintDefaults()
		os.Exit(0)
	}
	// Flush the logs upon exit
	defer glog.Flush()

	glog.Infof("===> Starting %s...", path.Base(os.Args[0]))

	if err := config.LoadConfig(conf); err != nil {
		glog.Fatalf("Cannot read configuration file: %s", err)

	}

	if err := server.Server(conf.AgentConfig); err != nil {
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

	// Set the values for log_dir and logtostderr.  Because this happens before flag.Parse(), cli arguments will override these.
	// Also set the DefValue parameter so -help shows the new defaults.
	// XXX - Make sure "glog" package is imported at this point, otherwise this will panic
	flagSet.Lookup("log_dir").DefValue = fmt.Sprintf("/var/log/%s", path.Base(os.Args[0]))
	flagSet.Lookup("logtostderr").DefValue = "false"
	flagSet.Lookup("stderrthreshold").DefValue = errorLogLevel

	flag.Parse()

	// Set log_dir -- either to given value or to the default + create the directory
	if mylogdir := flag.CommandLine.Lookup("log_dir").Value.String(); mylogdir != "" {
		os.MkdirAll(mylogdir, os.ModePerm)
	} else { // set it to default log_dir value
		flag.CommandLine.Lookup("log_dir").Value.Set(flag.CommandLine.Lookup("log_dir").DefValue)
		os.MkdirAll(flag.CommandLine.Lookup("log_dir").DefValue, os.ModePerm)
	}

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
        flagSet.Lookup("log_dir").DefValue = fmt.Sprintf("/var/log/%s", path.Base(os.Args[0]))
        flagSet.Lookup("logtostderr").DefValue = "false"
        flagSet.Lookup("stderrthreshold").DefValue = errorLogLevel

        flag.Parse()

        // Set log_dir -- either to given value or to the default + create the directory
        if mylogdir := flag.CommandLine.Lookup("log_dir").Value.String(); mylogdir != "" {
                os.MkdirAll(mylogdir, os.ModePerm)
        } else { // set it to default log_dir value
                flag.CommandLine.Lookup("log_dir").Value.Set(flag.CommandLine.Lookup("log_dir").DefValue)
                os.MkdirAll(flag.CommandLine.Lookup("log_dir").DefValue, os.ModePerm)
        }
}

*/
