package client

////
//// Common primitives for clients to the Nuage CNI Agent server
////

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/OpenPlatformSDN/nuage-cni/agent/types"
	"github.com/OpenPlatformSDN/nuage-cni/config"

	nuagecnitypes "github.com/OpenPlatformSDN/nuage-cni/types"
	"github.com/golang/glog"
	"github.com/nuagenetworks/vspk-go/vspk"
)

const (
	MAX_CONNS = 256             // How many simultaneous (pending) connections to the CNI agent server can we have
	MAX_IDLE  = 7 * time.Second // How long we should wait for CNI Agent server
	// Relative paths for the agent server
	NetconfPath   = "/cni/networks/"     // Agent server relative path for CNI NetConf
	ResultPath    = "/cni/interfaces/"   // Agent server relative path for CNI Result
	ContainerPath = "/nuage/containers/" // Agent server relative path for vspk.Container cache
)

// We assume that all Agent servers run on all host at the same "ServerPort"
var (
	Client     *http.Client
	ServerPort string
)

func InitClient(conf config.AgentConfig) error {

	// Pick up Agent server port from startup configuration
	ServerPort = conf.ServerPort

	certPool := x509.NewCertPool()

	if pemData, err := ioutil.ReadFile(conf.CaFile); err != nil {
		err = fmt.Errorf("Error loading CNI agent server CA certificate data from: %s. Error: %s", conf.CaFile, err)
		glog.Error(err)
		return err
	} else {
		certPool.AppendCertsFromPEM(pemData)
	}

	// configure a TLS client to use those certificates
	Client = new(http.Client)
	*Client = http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    types.MAX_CONNS,
			IdleConnTimeout: types.MAX_IDLE,
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
				// InsecureSkipVerify: true, // In case we want to skip server verification
			},
		},
	}

	return nil
}

////////
//////// Agent server operations
//////// XXX - Notes: The following assumptions are made:
//////// - Client (*http.Client) was initialized correctly i.e. InitClient() was called previously
//////// - No attempts are made to check if the hostname is a valid DNS entry (http.Client will issue an error)

// Poll for a given Container name at an agent running on host
func ContainerPoll(host, cname string) (*vspk.Container, error) {
	uri := "https://" + host + ":" + ServerPort + ContainerPath + cname
	reply, err := agentPoll(uri)

	if err != nil {
		glog.Errorf("--> Failed to fetch information for Container: %s from CNI Agent server. Agent server URI: %s . Error: %s ", cname, uri, err)
	}

	container := vspk.Container{}
	if jsonerr := json.Unmarshal(reply, &container); jsonerr != nil {
		return nil, fmt.Errorf("JSON decoding error: %s", jsonerr)
	}

	return &container, err
}

// Get a given Container using container name
func ContainerGET(host, cname string) (*vspk.Container, error) {
	container := vspk.Container{}
	uri := "https://" + host + ":" + ServerPort + ContainerPath + cname
	reply, err := agentGET(uri)

	if err != nil {
		glog.Errorf("--> Failed to GET data from CNI Agent server. Agent server URI: %s . Error: %s ", uri, err)
	} else {
		if jsonerr := json.Unmarshal(reply, &container); jsonerr != nil {
			return nil, fmt.Errorf("JSON decoding error: %s", jsonerr)
		}
	}

	return &container, err
}

// Use "vspk.Container.Name" as URI key
func ContainerPUT(host string, container *vspk.Container) error {
	uri := "https://" + host + ":" + ServerPort + ContainerPath + container.Name
	err := agentPUT(uri, container)
	if err != nil {
		glog.Errorf("--> Failed to PUT Container: %s to CNI Agent server. Agent server URI: %s . Error: %s", container.Name, uri, err)

	}
	return err
}

//  "cname" is container name
func ContainerDELETE(host string, cname string) error {
	uri := "https://" + host + ":" + ServerPort + ContainerPath + cname
	err := agentDELETE(uri)
	if err != nil {
		glog.Errorf("--> Failed to DELETE Container: %s from CNI Agent server. Agent server URI: %s . Error: %s", cname, uri, err)
	}

	return err
}

// PUT CNI Container Information at the agent server -- as  []nuagecnitypes.Result under the given key (normally, "vspk.Container.Name")
func ResultsPUT(host, key string, rez []nuagecnitypes.Result) error {
	uri := "https://" + host + ":" + ServerPort + ResultPath + key
	err := agentPUT(uri, rez)
	if err != nil {
		glog.Errorf("--> Failed to PUT CNI container information to CNI Agent server. Agent server URI: %s . Error: %s", uri, err)
	}
	return err
}

// DELETE CNI Container Information from agent server  -- (key is "vspk.Container.Name")
func ResultsDELETE(host, key string) error {
	uri := "https://" + host + ":" + ServerPort + ResultPath + key
	err := agentDELETE(uri)
	if err != nil {
		glog.Errorf("--> Failed to DELETE CNI container information from CNI Agent server. Agent server URI: %s . Error: %s", uri, err)
	}
	return err
}

////////
//////// Low-level utils
////////

// Polls Agent server at given uri. Polling with exponential backoff, time-out after MAX_IDLE
// Returns payload as []byte
func agentPoll(uri string) ([]byte, error) {

	//// XXX -- Timeouts. Adjust accordingly
	wait := 100 * time.Millisecond // Quite aggressive
	timeout := MAX_IDLE

	var agenterr error
	body := []byte{}

	// Waiting loop with exponential backoff...
	for t := wait; t < timeout; t = t * 2 {
		resp, err := Client.Get(uri)
		if err != nil {
			return nil, err
		}

		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			body, _ = ioutil.ReadAll(resp.Body)
			return body, nil

		case http.StatusNotFound:
			if agenterr == nil { // Do this only at the first poll that returns a 404, to speed things up
				body, _ = ioutil.ReadAll(resp.Body)
				agenterr = errors.New(string(body))
			}
			// Sleep (below) then try again
		default: // For any other response, bail out
			return body, fmt.Errorf("Agent server HTTP error: %s", resp.Status)
		}
		time.Sleep(t)
	}
	// After MAX_IDLE
	return body, agenterr
}

// PUT arbitrary data to agent server, JSON encoded
func agentPUT(uri string, data interface{}) error {
	req, _ := http.NewRequest("PUT", uri, nil)
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")

	buf := new(bytes.Buffer)

	if err := json.NewEncoder(buf).Encode(data); err != nil {
		glog.Errorf("JSON encoding error: %s", err)
		return err
	}

	req.Body = ioutil.NopCloser(buf)
	// ? Do we really need to do this (?)
	defer req.Body.Close()

	resp, err := Client.Do(req)
	if err != nil {
		glog.Errorf("Error sending 'PUT' HTTP request to agent server: %s", err)
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	default:
		body, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		return fmt.Errorf("Agent server error. Server response: %s. HTTP status: %s", string(body), resp.Status)
	}

}

// GET the data at given URI from the agent server
func agentGET(uri string) ([]byte, error) {
	req, _ := http.NewRequest("GET", uri, nil)
	resp, err := Client.Do(req)
	if err != nil {
		glog.Errorf("Error sending 'GET' HTTP request to agent server: %s", err)
		return []byte{}, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return body, nil
	}

	return body, fmt.Errorf("Agent server error. Server response: %s. HTTP status: %s", string(body), resp.Status)

}

// DELETE data at given URI from the agent server
func agentDELETE(uri string) error {
	req, _ := http.NewRequest("DELETE", uri, nil)

	resp, err := Client.Do(req)
	if err != nil {
		glog.Errorf("Error sending 'DELETE' HTTP request to agent server: %s", err)
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	default:
		body, _ := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		return fmt.Errorf("Agent server error. Server response: %s. HTTP status: %s", string(body), resp.Status)
	}

	return nil
}
