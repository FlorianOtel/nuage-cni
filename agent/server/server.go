package server

import (
	"encoding/json"
	"net/http"

	"github.com/OpenPlatformSDN/nuage-cni-plugin/agent/types"
	nuagecnitypes "github.com/OpenPlatformSDN/nuage-cni-plugin/types"

	"github.com/OpenPlatformSDN/nuage-cni-plugin/config"
	"github.com/OpenPlatformSDN/nuage-cni-plugin/errors"
	"github.com/nuagenetworks/vspk-go/vspk"

	"github.com/nuagenetworks/go-bambou/bambou"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
)

const (
	errorLogLevel = 2
)

var (
	// Nuage Containers cache -- containers running on this node
	// Key: vspk.Container.Name
	// - For K8S: <podName>_<podNs>.
	// - For runc: Container ID (Note: For cri-o containers the runc ID is actually an UUID, not  a name)
	Containers = make(map[string]vspk.Container)

	// Subnets with endpoints on the local node
	// XXX -- This cache is NOT necessarily consistent with the information in the VSD
	// Key: CNI network name  <-> vspk.Subnet.Name
	Networks = make(map[string]nuagecnitypes.NetConf)

	// Interfaces of containers running on this host
	// XXX - Since Nuage containers may have each interface, and each interface is part of a single 'Result', a container corresponds to []Result
	// Key:  vspk.Container.Name
	Interfaces = make(map[string][]nuagecnitypes.Result)
)

func Server(conf *config.Config) error {

	router := mux.NewRouter()

	////
	//// CNI Networks: Create/Retrieve/Delete CNI NetConf
	////
	// POST <-- NetConf
	router.HandleFunc(types.NetconfPath, PostNetwork).Methods("POST")
	// GET   --> NetConf
	router.HandleFunc(types.NetconfPath, GetNetworks).Methods("GET")
	router.HandleFunc(types.NetconfPath+"{name}", GetNetwork).Methods("GET")
	// DELETE <-- NetConf
	router.HandleFunc(types.NetconfPath+"{name}", DeleteNetwork).Methods("DELETE")

	////
	//// Cached Containers: Cache / retrieve vspk.Container (temporary cache; Contains entries / valid during the top part of split activation). Only PUT, GET, DELETE.
	////
	// PUT  <-- vspk.Container
	router.HandleFunc(types.ContainerPath+"{name}", PutContainer).Methods("PUT")
	// GET --> vspk.Container
	router.HandleFunc(types.ContainerPath, GetContainers).Methods("GET")
	router.HandleFunc(types.ContainerPath+"{name}", GetContainer).Methods("GET")
	// DELETE --> vspk.Container
	router.HandleFunc(types.ContainerPath+"{name}", DeleteContainer).Methods("DELETE")

	////
	////  CNI Interfaces: Create/Modify/Retreive/Delete []Result
	////  - Only PUT with a specific Name. "Name" convention may be specific to a platform. E.g. for K8S is <podName>_<podNameSpace>
	////
	// PUT
	router.HandleFunc(types.ResultPath+"{name}", PutContainerInterfaces).Methods("PUT")
	// GET --> Result
	router.HandleFunc(types.ResultPath, GetInterfaces).Methods("GET")
	router.HandleFunc(types.ResultPath+"{name}", GetContainerInterfaces).Methods("GET")
	// DELETE <-- uuid
	router.HandleFunc(types.ResultPath+"{name}", DeleteContainerInterfaces).Methods("DELETE")

	////
	////
	////
	return http.ListenAndServeTLS(":"+conf.AgentConfig.ServerPort, conf.AgentConfig.CertCaFile, conf.AgentConfig.KeyFile, router)
}

////////
//////// Util
////////

func sendjson(w http.ResponseWriter, data interface{}, httpstatus int) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(httpstatus)
	json.NewEncoder(w).Encode(data)
}

////////
//////// Handlers
////////

////
//// Containers
////

// Put container in local cache at specfic URI
// XXX - Notes
// - Different than "canonical" PUT -- i.e. no modify, only create at specific URI
// - Allow overwrites
func PutContainer(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	/*
		if _, exists := Containers[vars["name"]]; exists {
			glog.Warningf("Cannot cache Nuage Container with duplicate Name: %s", vars["name"])
			sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate+vars["name"], "A Nuge Container with given name already exists"), http.StatusConflict)
			return
		}
	*/

	newc := vspk.Container{}
	if err := json.NewDecoder(req.Body).Decode(&newc); err != nil {
		glog.Errorf("Container create request - JSON decoding error: %s", err)
		sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate+vars["name"], "JSON decoding error"), http.StatusBadRequest)
		return
	}

	////
	////  ...Any additional processing at Container caching
	////

	Containers[newc.Name] = newc

	////
	//// Response ....
	////

	glog.Infof("Successfully cached Nuage Container: %s", newc.Name)
	sendjson(w, nil, http.StatusCreated)
}

// List all cached containers
func GetContainers(w http.ResponseWriter, req *http.Request) {
	glog.Infof("Serving list of currently cached Nuage Containers")
	var resp []vspk.Container
	for _, container := range Containers {
		resp = append(resp, container)
	}
	sendjson(w, resp, http.StatusOK)
}

// Get container with given Name
func GetContainer(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if container, exists := Containers[vars["name"]]; exists {
		glog.Infof("Serving Nuage Container: %s", container.Name)
		sendjson(w, container, http.StatusOK)
	} else {
		glog.Warningf("Cannot find Nuage Container: %s", vars["name"])
		sendjson(w, bambou.NewBambouError(errors.ContainerNotFound+vars["name"], ""), http.StatusNotFound)
	}

}

// Delete container from cache
func DeleteContainer(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if container, exists := Containers[vars["name"]]; exists {
		glog.Infof("Deleting cached Nuage Container: %s", container.Name)
		////
		//// ... Any additional processing when deleting a container
		////
		delete(Containers, vars["name"])
	} else {
		glog.Warningf("Cannot find Nuage Container: %s", vars["name"])
		sendjson(w, bambou.NewBambouError(errors.ContainerNotFound+vars["name"], ""), http.StatusNotFound)
	}

}

////
//// Networks
////
func PostNetwork(w http.ResponseWriter, req *http.Request) {
	netconf := nuagecnitypes.NetConf{}
	if err := json.NewDecoder(req.Body).Decode(&netconf); err != nil {
		glog.Errorf("Network Configuration create request - JSON decoding error: %s", err)
		sendjson(w, bambou.NewBambouError(errors.NetworkCannotCreate, "JSON decoding error"), http.StatusBadRequest)
		return
	}

	if netconf.NetConf.Name == "" {
		glog.Warningf("Cannot create CNI Network Configuration with an empty name: %#v", netconf.NetConf)
		sendjson(w, bambou.NewBambouError(errors.NetworkCannotCreate, "Network Configuration lacks a valid name"), http.StatusBadRequest)
		return
	}

	if _, exists := Networks[netconf.NetConf.Name]; exists {
		glog.Warningf("Cannot create CNI Network Configuration with dulicate name: %s", netconf.NetConf.Name)
		sendjson(w, bambou.NewBambouError(errors.NetworkCannotCreate+netconf.NetConf.Name, "Network Configuration already exists"), http.StatusConflict)
		return
	}

	////
	////  ...Any additional processing at network creation
	//// - Scrubbing (?)

	Networks[netconf.NetConf.Name] = netconf

	////
	//// Response ....
	////

	glog.Infof("Successfully created CNI Network Configuration named: %s", netconf.NetConf.Name)
	sendjson(w, nil, http.StatusCreated)
}

func GetNetworks(w http.ResponseWriter, req *http.Request) {
	glog.Infof("Serving the list of local CNI Network Configurations")
	var resp []nuagecnitypes.NetConf
	for _, netw := range Networks {
		resp = append(resp, netw)
	}
	sendjson(w, resp, http.StatusOK)
}

func GetNetwork(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if mynetw, exists := Networks[vars["name"]]; exists {
		glog.Infof("Serving CNI Network Configuration: %s", mynetw.Name)
		sendjson(w, mynetw, http.StatusOK)
	} else {
		glog.Warningf("Cannot find CNI Network Configuration: %s", vars["name"])
		sendjson(w, bambou.NewBambouError(errors.NetworkNotFound+vars["name"], ""), http.StatusNotFound)
	}
}

func DeleteNetwork(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if mynetw, exists := Networks[vars["name"]]; exists {
		glog.Infof("Deleting CNI Network Configuration: %s", mynetw.Name)
		////
		//// ... Any additional processing when deleting a network
		////
		delete(Networks, vars["name"])
	} else {
		glog.Warningf("Cannot delete CNI Network Configuration: %s", vars["name"])
		sendjson(w, bambou.NewBambouError(errors.NetworkNotFound+vars["name"], ""), http.StatusNotFound)
	}
}

////
////  CNI Interfaces: Interfaces (running containers) in CNI Result format
////

func PostContainerInterfaces(w http.ResponseWriter, req *http.Request) {
	var containerifaces []nuagecnitypes.Result
	name := "" // Container Name (different than Sandbox Name!)

	if err := json.NewDecoder(req.Body).Decode(&containerifaces); err != nil {
		glog.Errorf("Container Interfaces create request - JSON decoding error: %s", err)
		sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate, "JSON decoding error"), http.StatusBadRequest)
		return
	}

	//// Scrub the input: It should have exactly one interface with the 'sandbox' field a non-empty string
	for _, rez := range containerifaces {
		for _, iface := range rez.Result.Interfaces {
			if iface.Sandbox != "" {
				if name == "" {
					name = iface.Sandbox
				} else {
					// We cannot have two interfaces with 'sandbox' field non-empty
					sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate+name, "Only one interface may specify the Container Name in the 'sandbox' field"), http.StatusBadRequest)
					return
				}
			}
		}
	}

	if name == "" {
		sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate, "Cannot find a valid Container Name in the 'sandbox' field"), http.StatusBadRequest)
		return
	}

	if _, exists := Interfaces[name]; exists {
		glog.Warningf("Cannot create interfaces for Container with duplicate Name: %s", name)
		sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate+name, "Network interfaces information for given container already exist"), http.StatusConflict)
		return
	}

	////
	////  ...Any additional processing at container interface creation
	//// - Scrubbing (?)

	/////
	Interfaces[name] = containerifaces

	////
	//// Response ....
	////

	glog.Infof("Successfully created Interfaces configuration for Container with Name: %s", name)
	sendjson(w, nil, http.StatusCreated)
}

// Create/Update Container interface information for a specific container Name
// XXX - Allow overwrites
func PutContainerInterfaces(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	/*
		if _, exists := Interfaces[vars["name"]]; exists {
			glog.Warningf("Container Interface information already exists for Container with Name: %s", vars["name"])
			sendjson(w, bambou.NewBambouError(errors.ContainerCannotCreate+vars["name"], "Container Interfaces already created"), http.StatusConflict)
			return
		}
	*/

	var containerifaces []nuagecnitypes.Result
	if err := json.NewDecoder(req.Body).Decode(&containerifaces); err != nil {
		glog.Errorf("Container Interfaces modify request - JSON decoding error: %s", err)
		sendjson(w, bambou.NewBambouError(errors.ContainerCannotModify+vars["name"], "JSON decoding error"), http.StatusBadRequest)
		return
	}

	////
	////  ...Any additional processing at container interface modification
	//// - (Scrubbing ?)

	Interfaces[vars["name"]] = containerifaces

	////
	//// Response ....
	////

	glog.Infof("Successfully modified CNI Interfaces configuration for Container: %s", vars["name"])
	sendjson(w, nil, http.StatusOK)
}

// Get all interfaces for all running containers
func GetInterfaces(w http.ResponseWriter, req *http.Request) {
	glog.Infof("Serving list of current CNI container interface information in CNI Result format")
	var resp [][]nuagecnitypes.Result
	for _, rez := range Interfaces {
		resp = append(resp, rez)
	}
	sendjson(w, resp, http.StatusOK)
}

// Get all interfaces of a given container
func GetContainerInterfaces(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if cifaces, exists := Interfaces[vars["name"]]; exists {
		glog.Infof("Serving in CNI Result format the interfaces for Container: %s", vars["name"])
		sendjson(w, cifaces, http.StatusOK)
	} else {
		glog.Warningf("Cannot find CNI interface information for Container: %s", vars["name"])
		sendjson(w, bambou.NewBambouError(errors.ContainerNotFound+vars["name"], ""), http.StatusNotFound)
	}
}

// Delete all interfaces of a given container
func DeleteContainerInterfaces(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	if _, exists := Interfaces[vars["name"]]; exists {
		glog.Infof("Deleting CNI interface information for Container: %s", vars["name"])
		delete(Interfaces, vars["name"])
	} else {
		glog.Warningf("Cannot delete CNI interface information for Container: %s", vars["name"])
		sendjson(w, bambou.NewBambouError(errors.ContainerNotFound+vars["name"], ""), http.StatusNotFound)
	}
}
