package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	agent "github.com/OpenPlatformSDN/cni-plugin/nuage-cni-agent/client"
	agenttypes "github.com/OpenPlatformSDN/cni-plugin/nuage-cni-agent/types"

	nuagecniconfig "github.com/OpenPlatformSDN/cni-plugin/config"
	nuagecnitypes "github.com/OpenPlatformSDN/cni-plugin/types"
	"github.com/containernetworking/cni/pkg/skel"
	currentcni "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/golang/glog"

	vrsdk "github.com/nuagenetworks/libvrsdk/api"

	"github.com/OpenPlatformSDN/cni-plugin/nuage-cni-plugin/util"
)

const (
	errorLogLevel       = 2
	k8sOrchestrationID  = "Kubernetes" // vspk.Container.OrchestrationID for Kubernetes
	runcOrchestrationID = "runc-dev"   // vspk.Container.OrchestrationID for runc (dev purposes only)
)

var (
	config        *nuagecniconfig.Config // Top level Plugin Configuration
	vrsConnection vrsdk.VRSConnection
	agentClient   *http.Client
	agentURLbase  string
	localhost     string
)

func main() {

	config = new(nuagecniconfig.Config)

	nuagecniconfig.Flags(config, flag.CommandLine)
	flag.Parse()

	if len(os.Args) == 1 { // With no arguments, print default usage
		flag.PrintDefaults()
		os.Exit(0)
	}
	// Flush the logs upon exit
	defer glog.Flush()

	glog.Infof("===> Starting %s...", path.Base(os.Args[0]))

	// Get local host name
	// XXX - The agent server certificate has to be issued for this host name.
	localhost, _ = os.Hostname()

	if err := nuagecniconfig.LoadConfig(config); err != nil {
		err = fmt.Errorf("Cannot read configuration file: %s", err)
		glog.Error(err)
		os.Exit(255)
	}

	if config.Orchestrator == "" {
		err := fmt.Errorf("Nuage CNI plugin client must specify a value for '-orchestrator' CLI option")
		glog.Error(err)
		os.Exit(255)
	}

	// Establish connection to the VRS
	var err error
	vrsConnection, err = util.ConnectToOVSDB(config)
	if err != nil {
		err = fmt.Errorf("Error connecting to VRS OVSDB: %s. Exiting...", err)
		glog.Error(err)
		os.Exit(255)
	}
	glog.Infof("Successfully established a connection to Nuage VRS")

	// Set up the connection to the local CNI agent server
	agentURLbase = "https://127.0.0.1:" + config.AgentConfig.ServerPort

	certPool := x509.NewCertPool()

	// XXX -- Note that "cacert.pem" actually also contains the server certificate as well, not only the CA. We need to use vanilla "ca.crt
	if pemData, err := ioutil.ReadFile(config.AgentConfig.CaFile); err != nil {
		err = fmt.Errorf("Error loading CA certificate data from: %s. Error: %s", config.AgentConfig.CaFile, err)
		glog.Error(err)
		os.Exit(255)
	} else {
		certPool.AppendCertsFromPEM(pemData)
	}

	// configure a TLS client to use trust those certificates
	agentClient = new(http.Client)
	*agentClient = http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    agenttypes.MAX_CONNS,
			IdleConnTimeout: agenttypes.MAX_IDLE,
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
				// InsecureSkipVerify: true, // In case we want to skip server verification
			},
		},
	}

	// Process CNI command
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.3.0"))

	// Disconnect from the VRS
	vrsConnection.Disconnect()

}

////////

////////
//////// Handlers
////////

// Top level dispatch functions
func cmdAdd(args *skel.CmdArgs) error {
	switch config.Orchestrator {
	case k8sOrchestrationID:
		return cmdAddK8S(args)
	default:
		err := fmt.Errorf("Unknown container orchestrator: %s", config.Orchestrator)
		glog.Error(err)
		return err
	}
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	switch config.Orchestrator {
	case k8sOrchestrationID:
		return cmdDelK8S(args)
	default:
		err := fmt.Errorf("Unknown container orchestrator: %s", config.Orchestrator)
		glog.Error(err)
		return err
	}
	return nil
}

////////
//////// Kubernetes
////////

var (
	podName, podNs string
	podUuid        string // The UUID for the K8S pod. Derived from K8S pod UID, encoded by the VSD agent in Nuage ContainerUUID. Different from Infrastructure Container UUID (args.ContainerID).
)

func cmdAddK8S(args *skel.CmdArgs) error {
	// XXX -- K8S passes additional arguments that we need: Pod Name and Pod namespace etc as such:
	// I0306 12:20:52.228215   24675 main.go:195] Nuage CNI plugin for Kubernetes: ADD command invoked with args: skel.CmdArgs{ContainerID:"38b2bc09d9d8a04404ef2af058f91d2feaf64c985de19f239b0ca66cfac9f039", Netns:"/proc/24622/ns/net", IfName:"eth0", Args:"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=ubuntu-14.04-sleep-1day;K8S_POD_INFRA_CONTAINER_ID=38b2bc09d9d8a04404ef2af058f91d2feaf64c985de19f239b0ca66cfac9f039", Path:"/opt/cni/bin:/opt/nuage/bin", StdinData:[]uint8{0x7b, 0xa, 0x20, 0x20, 0x20, 0x20, 0x22, 0x63, 0x6e, 0x69, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x20, 0x20, 0x22, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x22, 0x3a, 0x20, 0x22, 0x31, 0x37, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x31, 0x2e, 0x31, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x20, 0x20, 0x22, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x22, 0x3a, 0x20, 0x22, 0x31, 0x37, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x31, 0x2e, 0x30, 0x2f, 0x32, 0x34, 0x22, 0x2c, 0xa, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6e, 0x75, 0x61, 0x67, 0x65, 0x22, 0xa, 0x7d, 0xa}}

	/*
	   Args: [][2]string{
	           {"IgnoreUnknown", "1"},
	           {"K8S_POD_NAMESPACE", podNs},
	           {"K8S_POD_NAME", podName},
	           {"K8S_POD_INFRA_CONTAINER_ID", podInfraContainerID.ID},
	   }
	*/

	// XXX - Pretty ugly. There _should_ be a better way to do this (parse "env variables" from a string ? Use CNI_ARGS ?)
	for _, env := range strings.Split(args.Args, ";") {
		kvpair := strings.SplitN(env, "=", 2)
		switch kvpair[0] {
		case "K8S_POD_NAME":
			podName = kvpair[1]
		case "K8S_POD_NAMESPACE":
			podNs = kvpair[1]
		}
	}

	glog.Infof("Nuage CNI plugin for Kubernetes: ADD command invoked for: Pod Name: %s . Pod Namespace: %s , Infrastructure container UUID: %s", podName, podNs, args.ContainerID)

	// (???) Still TBD:  Anything to do with the Pod Namespace

	// We keep Container interface information in nuagecnitypes.Result. We update it as we built the interface
	// XXX - It contains both guest-side container interface information and host-side container information
	var cniIface nuagecnitypes.Result

	// Fetch container information from Nuage CNI Agent server
	// XXX - For K8S the "unique name" identifying a pod == vspk.Container.Name == "<podName>_<podNS>"
	cname := podName + "_" + podNs

	if container, err := agent.ContainerPoll(agentClient, localhost, config.AgentConfig.ServerPort, cname); err != nil {
		return err
	} else {
		cniIface = util.ContainerToResult(container)
		podUuid = container.UUID
	}

	// Unpick CNI Result into guest side and host side interfaces, resp ip config
	var giface, hiface *currentcni.Interface
	var gipconfig, hipconfig *currentcni.IPConfig

	for ifi, iface := range cniIface.Result.Interfaces {
		if iface.Sandbox != "" { // Only guest side interface have valid "Sandbox" fields
			giface = iface
			gipconfig = cniIface.Result.IPs[ifi]
		} else { // Host-side interface (temporary)
			hiface = iface
			hipconfig = cniIface.Result.IPs[ifi]
		}
	}

	// Update with the interfaces with the info we got from the Orchestrator (ContainerID, Sandbox, IfName, etc..)

	//// Guest side
	giface.Name = args.IfName
	if giface.Mac == "" {
		err := fmt.Errorf("Infrastructure container interface lacks a valid MAC address. Nuage Container details: Name: %s . UUID: %s", cname, podUuid)
		glog.Error(err)
		return err
	}
	giface.Sandbox = args.ContainerID // Update the actual Sandbox with args.ContainerID

	//// Host side
	// XXX - Notes:
	// - For interface name we're using the Infrastructure Container UUID - not Pod UUID -- as unique name prefix
	// - We will use same name for the VRS port name . OTOH for VRS entity UUID we need to use the podUuid (as set by the VSD)
	hiface.Name = string(args.ContainerID[:8]) + "-" + args.IfName
	if hiface.Mac == "" {
		hiface.Mac = util.GenerateMAC()
	}

	glog.Infof("Attaching K8S pod: %s . Network interface details: %#v . Host-side interface pair: %#v", podName, *giface, *hiface)

	// Setup veth pair btw "giface" (in container netns) and "hiface" (in host netns)
	if err := util.SetupVEth(args.Netns, giface, hiface); err != nil {
		glog.Errorf("K8S pod: %s - Error creating veth pair. Error: %s", podName, err)
		return err
	}
	glog.Infof("K8s Pod: %s - Successfully created a veth pair. Guest-side interface: %#v . Host-side interface: %#v", podName, *giface, *hiface)

	// Add host-side interface of veth pair to VRS bridge
	// XXX - We are using podUUID and "cname" as external-IDs in the VRS
	if err := util.VrsAddPort(config.VrsConfig.Bridge, hiface.Name, podUuid, cname); err != nil {
		glog.Errorf("K8S pod: %s - Error adding host-side interface: %s to VRS bridge: %s. Error: %s", podName, hiface.Name, config.VrsConfig.Bridge, err)
		return err
	}
	glog.Infof("K8S pod: %s - Attached host-side interface: %s to VRS bridge: %s", podName, hiface.Name, config.VrsConfig.Bridge)

	// Assign IP address to the container interface
	if err := util.AssignIP(args.Netns, giface, gipconfig); err != nil {
		glog.Errorf("K8S pod: %s - Error configuring container interface: %#v with IP address: %#s , IP Gateway: %s . Error: %s", podName, *giface, gipconfig.Address, gipconfig.Gateway, err)
		return err
	}

	glog.Infof("K8S pod: %s - Successfully configured container interface: %#v with IP address: %#s , IP Gateway: %s", podName, *giface, gipconfig.Address.String(), gipconfig.Gateway)

	// XXX - Notes
	// - Use hiface.Name as (unique) VRS port name
	// - Use "cname" and "podUUID" as entity name and, resp, UUID.
	if err := util.SplitActivation(vrsConnection, config.VrsConfig.Bridge, cname, podUuid, giface.Mac, hiface.Name); err != nil {
		glog.Errorf("K8S pod: %s - Error split activation: %s", podName, err)
		return err
	}

	glog.Infof("K8S pod: %s - Split Activation successful", podName)

	// Post CNI Result back to agent server as []nuagecnitypes.Result

	var rez []nuagecnitypes.Result
	rez = append(rez, cniIface)

	if err := agent.ResultsPUT(agentClient, localhost, config.AgentConfig.ServerPort, cname, rez); err != nil {
		return err

	}

	glog.Infof("Nuage CNI plugin completed -- Successfully configured K8S pod: %s . Container interface: %#v . Container IP address: %s . Host IP address: %s ", podName, *giface, gipconfig.Address.String(), hipconfig.Address.String())

	// We "return" the interface by printing it to stdout
	return cniIface.Print()
}

func cmdDelK8S(args *skel.CmdArgs) error {
	// XXX - Pretty ugly. There _should_ be a better way to do this (parse "env variables" from a string ? Use CNI_ARGS ?)
	for _, env := range strings.Split(args.Args, ";") {
		kvpair := strings.SplitN(env, "=", 2)
		switch kvpair[0] {
		case "K8S_POD_NAME":
			podName = kvpair[1]
		case "K8S_POD_NAMESPACE":
			podNs = kvpair[1]
		}
	}

	glog.Infof("Nuage CNI plugin for Kubernetes: DEL command invoked for: Pod Name: %s . Pod Namespace: %s , Infrastructure container UUID: %s", podName, podNs, args.ContainerID)

	// XXX - For K8S the "unique name" identifying a pod at the agent server  == vspk.Container.Name ==  "<podName>_<podNS>"
	cname := podName + "_" + podNs

	// Get Nuage ContainerUUID from the agent server - we used that as VRS entity UUID

	if container, err := agent.ContainerGET(agentClient, localhost, config.AgentConfig.ServerPort, cname); err != nil {
		return err
	} else {
		podUuid = container.UUID
	}

	// XXX - Notes
	// - As per ADD: entity name is "cname" and entity UUID is podUuid
	// - As a result of this the  container is removed from the VSD
	if err := util.DeleteVrsEntity(vrsConnection, config.VrsConfig.Bridge, cname, podUuid); err != nil {
		glog.Errorf("K8S pod: %s - Error removing from VRS Bridge entity: %s with UUID: %s . Error: %s", podName, cname, podUuid, err)
		return err
	}

	// XXX - Nuage container will be removed from local agent server by the platform plugin
	// agent.ContainerDELETE(agentClient, localhost, config.AgentConfig.ServerPort, cname)

	// Remove Pod's CNI Interface information from agent server -- Ignore any errors
	agent.ResultsDELETE(agentClient, localhost, config.AgentConfig.ServerPort, cname)

	glog.Infof("Nuage CNI plugin completed -- Successfully removed pod: %s", podName)

	return nil
}
