package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/OpenPlatformSDN/nuage-cni/config"
	nuagecnitypes "github.com/OpenPlatformSDN/nuage-cni/types"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	currentcni "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/golang/glog"
	vrsdk "github.com/nuagenetworks/libvrsdk/api"
	"github.com/nuagenetworks/libvrsdk/api/entity"
	"github.com/nuagenetworks/libvrsdk/api/port"
	"github.com/nuagenetworks/vspk-go/vspk"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Run shell command -  Stoken from Brent / Dave
func run(cmd string, args ...string) (bytes.Buffer, bytes.Buffer, error) {
	var stdout, stderr bytes.Buffer
	glog.Infof("Executing shell command: [%#v] with args: [%#v]", cmd, args)
	command := exec.Command(cmd, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout, stderr, err
}

// Generate MAC address

func GenerateMAC() string {
	buf := make([]byte, 6)
	rand.Seed(time.Now().UTC().UnixNano())
	rand.Read(buf)
	// Set the local bit -- Note the setting of the local bit which means it won't clash with any globally administered addresses (see wikipedia for more info)
	// XXX -- This does _NOT_ work for Nuage VSD
	// buf[0] |= 2
	// XXX - For Nuage VSD
	buf[0] = buf[0]&0xFE | 0x02
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

// Find first external IPv4 address, or "0.0.0.0/8"
func myexternalIPv4() net.IPNet {
	noIPv4 := net.IPNet{net.ParseIP("0.0.0.0"), net.ParseIP("0.0.0.0").DefaultMask()}

	ifaces, err := net.Interfaces()
	if err != nil {
		return noIPv4
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return noIPv4
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ip = ip.To4()
				if ip == nil {
					continue // not an ipv4 address
				}
				return *v
			}
		}
	}
	return noIPv4
}

// maps a vspk.Subnet to CNI NetConf
func SubnetToNetConf(vspksubnet vspk.Subnet) nuagecnitypes.NetConf {
	cidr := net.IPNet{net.ParseIP(vspksubnet.Address), net.IPMask(net.ParseIP(vspksubnet.Netmask))}
	return nuagecnitypes.NetConf{
		NetConf: cnitypes.NetConf{
			CNIVersion: version.Current(),
			Name:       vspksubnet.Name,
			Type:       nuagecnitypes.NuageCNIPlugin,
		},
		ID:      vspksubnet.ID,
		Prefix:  cidr.String(),
		Gateway: vspksubnet.Gateway,
	}
}

// maps a vspk.Container to a 'nuagecnitypes.Result'

// XXX - Notes:
// - While vspk.Container may have multiple interfaces, we are reporting only the first one. Terminate if otherwise.
// - For each container interface (guest-side interface) we report the "HypervisorIP" as host-side pair
// - Workaround SDK bug: "vspk.Container.Interfaces" is not "[]ContainerInterface" so it unmarshalls into "map[string]interface{}".  As such we access it as a "map[string]interface{}
func ContainerToResult(container *vspk.Container) nuagecnitypes.Result {

	if len(container.Interfaces) != 1 {
		glog.Fatalf("Fatal error converting Nuage Container to CNI Result: Given container does not have exactly one interface. Container info: %#v", *container)
	}

	rez := currentcni.Result{}

	//XXX - "container.Interfaces[0]" is "map[string]interface{}" (arbitrary JSON object) instead of a "ContainerInterface"
	// We deal with that by JSON marshalling & unmarshalling in the (right) type
	data, _ := json.Marshal(container.Interfaces[0])
	ciface := vspk.ContainerInterface{}
	json.Unmarshal(data, &ciface)

	ifindex := 0 // Interface index in the CNI `Result`

	giface := currentcni.Interface{
		Name:    ciface.Name,
		Mac:     ciface.MAC,
		Sandbox: container.UUID, // XXX -- Temporary. Caller will replace this with actual Sandbox UUID
	}
	rez.Interfaces = append(rez.Interfaces, &giface)

	// XXX - KISS: Only IPv4 addresses for now.
	// TBD: Add logic for IPv6
	gipconfig := currentcni.IPConfig{
		Version:   "4",
		Interface: ifindex,
		Address:   net.IPNet{net.ParseIP(ciface.IPAddress), net.IPMask(net.ParseIP(ciface.Netmask))},
		Gateway:   net.ParseIP(ciface.Gateway),
	}
	rez.IPs = append(rez.IPs, &gipconfig)

	////
	//// Still TBD -- Add logic for Routes (VSD FIPs ?) and DNS (?)
	////

	ifindex++
	//Corresponding Host-side interface
	hiface := currentcni.Interface{
		Name: "Temporary -- host-side interface name", // XXX - Caller will replace this with actual host-side iface name
	}
	rez.Interfaces = append(rez.Interfaces, &hiface)

	// XXX - Notes / Still TBD / Fix Me.
	// - KISS: Only IPv4 addresses for now. TBD: Add logic for IPv6
	// - Use HypervisorIP for the container as "host ip address". (i.e. underlay address). _Assume_ (!!!) default mask for it
	// - (??) "HypervisorIP" in Nuage can be e.g.  "172.16.254.12,0,1"
	// - For split activation though, the value for "hypervisorIP" is "FFFFFF" (net.ParseIP returns 'nil'). In that case use "0.0.0.0".

	var haddr net.IPNet // Container host address

	hypervisorIP := net.ParseIP(strings.Split(container.HypervisorIP, ",")[0])

	// Temporary: Use the first non-loopback IPv4 address of the container host as address if none was above
	if hypervisorIP == nil {
		haddr = myexternalIPv4()
	} else {
		haddr = net.IPNet{hypervisorIP, hypervisorIP.DefaultMask()} // XXX -- Use default mask for this IP address
	}

	hipconfig := currentcni.IPConfig{
		Version:   "4",
		Interface: ifindex,
		Address:   haddr,
	}
	rez.IPs = append(rez.IPs, &hipconfig)

	return nuagecnitypes.Result{
		CNIVersion: rez.Version(),
		Result:     rez,
	}
}

// Set up a veth pair between container netns and host netns
func SetupVEth(cnetns string, giface, hiface *currentcni.Interface) error {

	gifacemac, _ := net.ParseMAC(giface.Mac)
	hifacemac, _ := net.ParseMAC(hiface.Mac)

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	orignetns, _ := netns.Get()
	defer orignetns.Close()

	var cnetnsfd netns.NsHandle
	var err error

	// Get a FD handle to the container netns
	if cnetnsfd, err = netns.GetFromPath(cnetns); err != nil {
		glog.Errorf("Failed to open container netns: %s . Error: %s", cnetns, err)
		return err
	}

	// Create veth pair
	// Set temporary iface name for the container-side interface (veth peer) to "<hiface.Name>-g". This will be changed once in right namespace to giface.Name

	gVeth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hiface.Name + "-g",
			// MTU:          1460,
			// HardwareAddr: gifacemac,    // XXX -- For some reason setting it here doesn't work -- MAC address gets changed once we moved netspaces (?!?)
		},
		PeerName: hiface.Name,
	}

	if err = netlink.LinkAdd(gVeth); err != nil {
		glog.Errorf("Failed to create veth pair. Error: %s", err)
		return err
	}

	// Get a handle on the host-side interface
	var hVeth netlink.Link

	if hVeth, err = netlink.LinkByName(hiface.Name); err != nil {
		glog.Errorf("Failed to lookup host-side interface of veth pair: %s . Error: %s", hiface.Name, err)
		netlink.LinkDel(gVeth)
		return err
	}

	// Put guest interface in the container netspace
	if err = netlink.LinkSetNsFd(gVeth, int(cnetnsfd)); err != nil {
		glog.Errorf("Failed to move veth pair interface into container netns: %s . Error: %s", cnetns, err)
		netlink.LinkDel(gVeth)
		return err
	}

	// XXX - Switch to container netns
	if err = netns.Set(cnetnsfd); err != nil {
		glog.Errorf("Failed to switch to container netns: %s . Error: %s", cnetns, err)
		netlink.LinkDel(gVeth)
		return err
	}
	// 1) Change the name to its correct name
	if err = netlink.LinkSetName(gVeth, giface.Name); err != nil {
		glog.Errorf("Failed to set container interface name to: %s . Error: %s", giface.Name, err)
		netlink.LinkDel(gVeth)
		return err
	}

	// 2)  Set MAC address
	if err = netlink.LinkSetHardwareAddr(gVeth, gifacemac); err != nil {
		glog.Errorf("Failed to set MAC address of container-side interface for veth pair: %s . MAC: %s . Error: %s", giface.Name, giface.Mac, err)
		netlink.LinkDel(gVeth)
		return err
	}

	// 3) Bring container side of interface up
	if err = netlink.LinkSetUp(gVeth); err != nil {
		glog.Errorf("Failed to enable container-side interface of veth pair. Error: %s", err)
		netlink.LinkDel(gVeth)
		return err
	}

	// Switch back to host netns
	netns.Set(orignetns)

	// Set additional info for the host-side interface : MAC address
	if err = netlink.LinkSetHardwareAddr(hVeth, hifacemac); err != nil {
		glog.Errorf("Failed to set MAC address of host-side interface for veth pair: %s . MAC: %s . Error: %s", hiface.Name, hiface.Mac, err)
		netlink.LinkDel(gVeth)
		return err
	}

	/*
	   // Set Name
	   // XXX - Still TBD if this is really needed or it's picked up from "PeerName" above
	   if err := netlink.LinkSetName(hVeth, hiface.Name); err != nil {
	           glog.Errorf("Failed to set Name of host-side interface for veth pair: %s . Error: %s", hiface.Name, err)
	           netlink.LinkDel(hVeth)
	           return err
	   }
	*/

	// Bring host-side interface up
	if err = netlink.LinkSetUp(hVeth); err != nil {
		glog.Errorf("Failed to enable host-side of veth pair: %s . Error: %s", hiface.Name, err)
		netlink.LinkDel(gVeth)
		return err
	}

	return nil
}

// Container Split activation
func SplitActivation(vrsConn vrsdk.VRSConnection, bridge, eName, eUuid, ifMac, portName string) error {

	// Create Port Attributes
	portAttributes := port.Attributes{
		MAC:      ifMac,
		Platform: entity.Container,
		Bridge:   bridge,
	}

	// Port Metadata -- empty strings for split activation
	portMetadata := make(map[port.MetadataKey]string)
	portMetadata[port.MetadataKeyDomain] = ""
	portMetadata[port.MetadataKeyNetwork] = ""
	portMetadata[port.MetadataKeyZone] = ""
	portMetadata[port.MetadataKeyNetworkType] = ""

	// Create a entry in Nuage Port Table
	if err := vrsConn.CreatePort(portName, portAttributes, portMetadata); err != nil {
		glog.Errorf("Split Activation: Error creating port: %s in Nuage Port table. Error: %s", portName, err)
		return err
	}

	// Populate container metadata
	containerMetadata := make(map[entity.MetadataKey]string)
	containerMetadata[entity.MetadataKeyUser] = ""
	containerMetadata[entity.MetadataKeyEnterprise] = ""
	// XXX -- Cargo-culting: Without this the port is not discovered by the VRS
	containerMetadata[entity.MetadataKeyExtension] = "true"

	// Define ports associated with the container
	ports := []string{portName}

	// Add container entity to VRS
	entityInfo := vrsdk.EntityInfo{
		UUID:     eUuid,
		Name:     eName,
		Domain:   entity.Docker,
		Type:     entity.Container,
		Ports:    ports,
		Metadata: containerMetadata,
	}

	if err := vrsConn.CreateEntity(entityInfo); err != nil {
		glog.Errorf("Error creating an entity in VRS Entity table: %s", err)
		return err
	}

	glog.Infof("Split Activation: Successfully created entity in VRS Entity table")

	// Notify VRS that the container has booted
	if err := vrsConn.PostEntityEvent(eUuid, entity.EventCategoryStarted, entity.EventStartedBooted); err != nil {
		glog.Errorf("Error sending booting event to VRS: %s", err)
		return err
	}

	glog.Infof("Split Activation: Successfully sent booting event to VRS for container: %s", eName)

	return nil
}

// Assign Container (given as netspace) interface with IP address
func AssignIP(cnetns string, ciface *currentcni.Interface, cipconfig *currentcni.IPConfig) (err error) {

	err = ns.WithNetNSPath(cnetns, func(hostNS ns.NetNS) error {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ciflink, errnetlink := netlink.LinkByName(ciface.Name)
		if errnetlink != nil {
			glog.Errorf("Failed to lookup interface with Name: %s. Error: %s", ciface.Name, errnetlink)
			return errnetlink
		}

		err = netlink.AddrAdd(ciflink, &netlink.Addr{IPNet: &cipconfig.Address})
		if err != nil {
			glog.Errorf("Error assigning IP address: %s for container interface with Name: %s. Error: %s", cipconfig.Address, ciface.Name, err)
			return err
		}

		// Add a connected route to a dummy next hop so that a default route can be set
		gwNet := &net.IPNet{IP: cipconfig.Gateway, Mask: net.CIDRMask(32, 32)}

		if err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: ciflink.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       gwNet}); err != nil {
			glog.Errorf("Error setting a dummy next hop for container interface: %s. Error: %s", ciface.Name, err)
			return err
		}

		if err = ip.AddDefaultRoute(cipconfig.Gateway, ciflink); err != nil {
			glog.Errorf("Error setting default gateway to: %s for container interface: %s. Error: %s", cipconfig.Gateway, ciface.Name, err)
			return err
		}

		/*
			// Add a default route for gateway
			defroute := netlink.Route{
				LinkIndex: ciflink.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       &net.IPNet{nil, nil},
				Gw:        cipconfig.Gateway,
			}

			err = netlink.RouteAdd(&defroute)

			if err != nil {
				glog.Errorf("Error setting default gateway to: %s for container interface with Name: %s. Error: %s", cipconfig.Gateway, ciface.Name, err)
				return err
			}
		*/

		return nil
	})

	return err
}

func DeleteVrsEntity(vrsConn vrsdk.VRSConnection, bridge, eName, eUuid string) error {

	// Obtain all ports associated with this container entity
	portlist, _ := vrsConn.GetEntityPorts(eUuid)

	// Notify VRS that the container is shutting down
	if err := vrsConn.PostEntityEvent(eUuid, entity.EventCategoryStopped, entity.EventStoppedShutdown); err != nil {
		glog.Errorf("Error sending stopped event to VRS: %s", err)
		return err
	}

	glog.Infof("Successfully sent stopped event for entity with UUID: %s to VRS", eUuid)

	// Remove the entity from the VRS Entity table
	if err := vrsConn.DestroyEntity(eUuid); err != nil {
		glog.Errorf("Failed to entity with UUID: %s from VRS entity table. Error: %s", eUuid, err)
		return err
	}

	glog.Infof("Successfully removed entity with UUID: %s from VRS", eUuid)

	for _, port := range portlist {
		// Performing cleanup of port/entity on VRS
		if err := vrsConn.DestroyPort(port); err != nil {
			glog.Errorf("Failed to delete port: %s from VRS port table. Error: %s", port, err)
			return err
		}
		glog.Infof("Successfully deleted port: %s from VRS port table for VRS entity with UUID: %s", port, eUuid)

		// Delete veth port from VRS bridge
		if err := VrsDelPort(bridge, port); err != nil {
			glog.Errorf("Failed to remove veth port: %s from VRS bridge: %s . Error: %s", port, bridge, err)
			return err
		}

		glog.Infof("Successfully removed veth port: %s from VRS bridge: %s", port, bridge)

		// Remove the veth pair
		if ciflink, err := netlink.LinkByName(port); err != nil {
			glog.Errorf("Failed to lookup interface with Name: %s. Error: %s", port, err)
			return err
		} else {
			if err := netlink.LinkDel(ciflink); err != nil {
				glog.Errorf("Failed to delete interface with Name: %s. Error: %s", port, err)
				return err
			}
		}
		glog.Infof("Successfully deleted  veth pair for interface: %s", port)
	}

	return nil
}

// ConnectToOVSDB -- connect to VRS OVSDB via unix socket
func ConnectToOVSDB(conf *config.Config) (vrsdk.VRSConnection, error) {
	vrsConnection, err := vrsdk.NewUnixSocketConnection(conf.VrsConfig.Endpoint)
	if err != nil {
		return vrsConnection, fmt.Errorf("Cannot connect to VRS via UNIX socket. Error: %s", err)
	}

	return vrsConnection, nil
}

// Add a port to a VRS bridge -- llam-glam
func VrsAddPort(bridge, port, cuuid, cname string) error {
	stdout, stderr, err := run("ovs-vsctl", "--no-wait", "--if-exists", "del-port", bridge, port, "--", "add-port", bridge, port, "--", "set", "interface", port, "external-ids={vm-uuid="+cuuid+",vm-name="+cname+"}")
	if err != nil {
		errmsg := stderr.String()
		glog.Errorf("Error executing shell command. Command stderr: %s . Error: %s", errmsg, err)
		return err
	}

	glog.Infof("Shell command executed successfully. Command stdout: %s", stdout.String())
	return nil
}

// Delete a port from a VRS bridge -- llam-glam
func VrsDelPort(bridge, port string) error {
	stdout, stderr, err := run("ovs-vsctl", "--no-wait", "del-port", bridge, port)
	if err != nil {
		errmsg := stderr.String()
		glog.Errorf("Error executing shell command. Command stderr: %s . Error: %s", errmsg, err)
		return err
	}

	glog.Infof("Shell command executed successfully. Command stdout: %s", stdout.String())
	return nil
}

// Get local hostname
