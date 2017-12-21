package config

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	yaml "gopkg.in/yaml.v2"
)

// Configuration file -- Same data structure for both CNI agent and CNI plugin, but they will use different fields (different configuration file entries & CLI flag parsing)
// XXX - the embedded types with same name are for YAML (un)marshalling purposes

// XXX - Still TBD if we still need this, or different components should define their own variant hereof

type Config struct {
	// Only available as CLI options
	Orchestrator string `yaml:"-"`
	ConfigFile   string `yaml:"-"`
	// Config file fields
	VrsConfig   VrsConfig   `yaml:"vrs-config"`
	AgentConfig AgentConfig `yaml:"agent-config"`
}

type VrsConfig struct {
	Endpoint string `yaml:"endpoint"`
	Bridge   string `yaml:"ovs-bridge"`
}

type AgentConfig struct {
	ServerPort string `yaml:"server-port"` // CNI Agent server port
	CaFile     string `yaml:"caFile"`      // CNI Agent server CA certificate
	CertCaFile string `yaml:"certcaFile"`  // CNI Agent server certificate + CA certificate (concatenated, in PEM format)
	KeyFile    string `yaml:"keyFile"`     // CNI Agent server private key
}

////////
////////
////////

func Flags(conf *Config, flagSet *flag.FlagSet) {
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

func LoadConfig(conf *Config) error {
	data, err := ioutil.ReadFile(conf.ConfigFile)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, conf); err != nil {
		return err
	}

	return nil
}
