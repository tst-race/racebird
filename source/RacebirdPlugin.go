//
// Copyright 2025 Two Six Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// RacebirdPlugin Interface. Is a Golang  implementation of the RACE T2 Plugin. Will
// perform obfuscated communication for the RACE system.

package main

import "C"

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	transports "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"io"
	"io/ioutil"
	"net"
	"path"
	"regexp"
	commsShims "shims"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

const (
	CONN_TYPE         = "tcp"
	CHANNEL_GID       = "obfs4"
	FRAME_HEADER_SIZE = 8

	nodeIDArg     = "node-id"
	publicKeyArg  = "public-key"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"
	iatArg        = "iat-mode"
	certArg       = "cert"

	biasCmdArg = "obfs4-distBias"
)

type linkAddress struct {
	Addr string `json:"addr"`
	Cert string `json:"cert"`
	Iat  string `json:"iat"`
}

func (plugin *RacebirdPlugin) ActivateChannel(handle uint64, channelGid string, roleName string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("ActivateChannel: (handle: %v, channel CHANNEL_GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	if channelGid != CHANNEL_GID {
		logError(logPrefix, "unknown channel CHANNEL_GID")
		return commsShims.PLUGIN_ERROR
	}

	if plugin.status == commsShims.CHANNEL_AVAILABLE {
		return commsShims.PLUGIN_OK
	}

	plugin.status = commsShims.CHANNEL_STARTING
	response := plugin.sdk.RequestCommonUserInput("hostname")
	plugin.paramRequestHandles[response.GetHandle()] = "hostname"

	for paramName := range plugin.obfsParams {
		response = plugin.sdk.RequestPluginUserInput(paramName, "Enter value for "+paramName, true)
		plugin.paramRequestHandles[response.GetHandle()] = paramName
	}
	return commsShims.PLUGIN_OK
}

func (plugin *RacebirdPlugin) DeactivateChannel(handle uint64, channelGid string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("DeactivateChannel: (handle: %v, channel CHANNEL_GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	if len(plugin.linkAddresses) > 0 {
		logError(logPrefix, "refusing to deactivate channel with existing links (should call DestroyLink on all links first)")
		return commsShims.PLUGIN_ERROR
	}

	plugin.status = commsShims.CHANNEL_UNAVAILABLE
	plugin.sdk.OnChannelStatusChanged(handle, channelGid, commsShims.CHANNEL_UNAVAILABLE, commsShims.NewChannelProperties(), commsShims.GetRACE_BLOCKING())

	if plugin.status == commsShims.CHANNEL_UNAVAILABLE {
		return commsShims.PLUGIN_OK
	}

	linkIdsToDestroy := []string{}
	for linkId, linkProps := range plugin.linkProperties {
		if linkProps.GetChannelGid() == channelGid {
			linkIdsToDestroy = append(linkIdsToDestroy, linkId)
		}
	}

	for _, linkId := range linkIdsToDestroy {
		// Calls OnLinkStatusChanged to notify SDK that links have been destroyed and call OnConnectionStatusChanged to notify all connnections in each link have been destroyed.
		plugin.DestroyLink(handle, linkId)
	}

	return commsShims.PLUGIN_OK
}

func (plugin *RacebirdPlugin) OnUserInputReceived(handle uint64, answered bool, response string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("OnUserInputReceived: (handle: %v): ", handle)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	paramName, exists := plugin.paramRequestHandles[handle]
	if !exists {
		logWarning(logPrefix, "handle is not recognized")
		return commsShims.PLUGIN_ERROR
	}
	delete(plugin.paramRequestHandles, handle)
	if paramName == "hostname" {
		if answered {
			plugin.hostname = response
			logDebug(logPrefix, "using hostname ", plugin.hostname)
		} else {
			plugin.hostname = ""
			logInfo(logPrefix, "no hostname provided, can only act as a client (Loader)")
		}
	} else {
		if answered {
			plugin.obfsParams[paramName] = response
			logDebug(logPrefix, "parameter received: "+paramName+" = "+response)
		} else {
			logInfo(logPrefix, "parameter "+paramName+" was not provided, using default: "+plugin.obfsParams[paramName])
		}
	}

	// Check if all requests have been fulfilled
	if len(plugin.paramRequestHandles) == 0 {
		plugin.nextAvailablePort, _ = strconv.Atoi(plugin.obfsParams["start-port"])
		plugin.status = commsShims.CHANNEL_AVAILABLE
		channelProps := plugin.sdk.GetChannelProperties(CHANNEL_GID)
		plugin.sdk.OnChannelStatusChanged(
			commsShims.GetNULL_RACE_HANDLE(),
			CHANNEL_GID,
			commsShims.CHANNEL_AVAILABLE,
			channelProps,
			commsShims.GetRACE_BLOCKING(),
		)
		plugin.sdk.DisplayInfoToUser(fmt.Sprintf("%v is available", CHANNEL_GID), commsShims.UD_TOAST)
	}

	return commsShims.PLUGIN_OK
}

// Forces interface to be a superset of the abstract base class
// Go type to define abstract methods.
type RacebirdPlugin struct {
	sdk                 commsShims.IRaceSdkComms
	connections         map[string]*net.Conn
	linkConnectionCount map[string]int
	connectionsMutex    sync.RWMutex
	linkIsLoader        map[string]bool
	linkProperties      map[string]commsShims.LinkProperties
	linkAddresses       map[string]linkAddress
	listenerSockets     map[string]*net.Listener
	serverFactories     map[string]base.ServerFactory
	status              commsShims.ChannelStatus
	hostname            string
	recvChannel         chan int
	nextAvailablePort   int
	paramRequestHandles map[uint64]string
	obfsParams          map[string]string
}

// Wrapper for debug level logging using the RACE Logging API call
func logDebug(msg ...interface{}) {
	commsShims.RaceLogLogDebug("RacebirdPlugin", fmt.Sprint(msg...), "")
}

// Wrapper for info level logging using the RACE Logging API call
func logInfo(msg ...interface{}) {
	commsShims.RaceLogLogInfo("RacebirdPlugin", fmt.Sprint(msg...), "")
}

// Wrapper for warn level logging using the RACE Logging API call
func logWarning(msg ...interface{}) {
	commsShims.RaceLogLogWarning("RacebirdPlugin", fmt.Sprint(msg...), "")
}

// Wrapper for error level logging using the RACE Logging API call
func logError(msg ...interface{}) {
	commsShims.RaceLogLogError("RacebirdPlugin", fmt.Sprint(msg...), "")
}

// LinkPropSetJson represents a list of properties associated with the link. These include
// information useful for the network manager/core to choose which links to use for different types of
// communication
type LinkPropSetJson struct {
	Bandwidth_bps int     `json:"bandwidth_bps"`
	Latency_ms    int     `json:"latency_ms"`
	Loss          float32 `json:"loss"`
}

// Creates and returns a new LinkPropSet
func NewLinkPropertySet(json LinkPropSetJson) commsShims.LinkPropertySet {
	propSet := commsShims.NewLinkPropertySet()
	propSet.SetBandwidth_bps(json.Bandwidth_bps)
	propSet.SetLatency_ms(json.Latency_ms)
	propSet.SetLoss(json.Loss)
	return propSet
}

// LinkPropPairJson holds the send and receive properites of a connection. This
// includes a LinkPropSetJson for the send and receive side of the connection.
type LinkPropPairJson struct {
	Send    LinkPropSetJson `json:"send"`
	Receive LinkPropSetJson `json:"receive"`
}

// Creates and returns a new LinkPropPair
func NewLinkPropertyPair(json LinkPropPairJson) commsShims.LinkPropertyPair {
	propPair := commsShims.NewLinkPropertyPair()
	propPair.SetSend(NewLinkPropertySet(json.Send))
	propPair.SetReceive(NewLinkPropertySet(json.Receive))
	return propPair
}

// LinkPropJson represents the complete properties for a given link. This includes
// details about the link, properties (best/worst/expected cases), and what
// type of link the link is
type LinkPropJson struct {
	Linktype        string           `json:"type"`
	Reliable        bool             `json:"reliable"`
	Duration_s      int              `json:"duration_s"`
	Period_s        int              `json:"period_s"`
	Mtu             int              `json:"mtu"`
	Worst           LinkPropPairJson `json:"worst"`
	Best            LinkPropPairJson `json:"best"`
	Expected        LinkPropPairJson `json:"expected"`
	Unicast         bool             `json:"unicast"`
	Multicast       bool             `json:"multicast"`
	Supported_hints []string         `json:"supported_hints"`
}

// Unmarshal the data object into a LinkPropJson
func (t *LinkPropJson) UnmarshalJSON(data []byte) error {
	type alias LinkPropJson
	tmpSet := LinkPropSetJson{
		Bandwidth_bps: -1,
		Latency_ms:    -1,
		Loss:          -1.0,
	}
	tmpPair := LinkPropPairJson{
		Send:    tmpSet,
		Receive: tmpSet,
	}
	tmp := &alias{
		Duration_s: -1,
		Period_s:   -1,
		Mtu:        -1,
		Worst:      tmpPair,
		Best:       tmpPair,
		Expected:   tmpPair,
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	*t = LinkPropJson(*tmp)
	return nil
}

// Set the Sdk object and perform minimum work to
// be able to respond to incoming calls.
func (plugin *RacebirdPlugin) Init(pluginConfig commsShims.PluginConfig) commsShims.PluginResponse {
	logDebug("Init called")
	defer logDebug("Init returned")
	plugin.linkAddresses = make(map[string]linkAddress)
	plugin.linkProperties = make(map[string]commsShims.LinkProperties)
	plugin.linkIsLoader = make(map[string]bool)
	plugin.listenerSockets = make(map[string]*net.Listener)
	plugin.serverFactories = make(map[string]base.ServerFactory)
	plugin.connections = make(map[string]*net.Conn)
	plugin.linkConnectionCount = make(map[string]int)
	plugin.paramRequestHandles = make(map[uint64]string)
	plugin.obfsParams = map[string]string{
		nodeIDArg:     "",
		privateKeyArg: "",
		seedArg:       "",
		iatArg:        "0",
		"start-port":  "8675",
	}
	transports.Init()

	return commsShims.PLUGIN_OK
}

// Shutdown the plugin. Close open connections, remove state, etc.
func (plugin *RacebirdPlugin) Shutdown() commsShims.PluginResponse {
	logDebug("Shutdown: called")
	defer logDebug("Shutdown: returned")
	handle := commsShims.GetNULL_RACE_HANDLE()
	// Clean up everything
	for connectionId, _ := range plugin.connections {
		plugin.CloseConnection(handle, connectionId)
	}
	
	for linkId, _ := range plugin.linkAddresses {
		plugin.DestroyLink(handle, linkId)
	}

	plugin.DeactivateChannel(handle, CHANNEL_GID)
	
	return commsShims.PLUGIN_OK
}

// Send an encrypted package
func (plugin *RacebirdPlugin) SendPackage(handle uint64, connectionId string, encPkg commsShims.EncPkg, timeoutTimestamp float64, batchId uint64) commsShims.PluginResponse {
	defer commsShims.DeleteEncPkg(encPkg)
	logPrefix := fmt.Sprintf("SendPackage: (handle: %v, connectionId: %v): ", handle, connectionId)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	// get the raw bytes out of the Encrypted Package
	msg_vec := encPkg.GetRawData()
	defer commsShims.DeleteByteVector(msg_vec)
	msg := make([]byte, msg_vec.Size()+FRAME_HEADER_SIZE)
	msg_size := uint64(msg_vec.Size())
	length_bytes := make([]byte, FRAME_HEADER_SIZE)
	binary.BigEndian.PutUint64(length_bytes, msg_size)
	copy(msg[0:FRAME_HEADER_SIZE], length_bytes[:])
	for i := 0; i < int(msg_size); i++ {
		msg[FRAME_HEADER_SIZE+i] = msg_vec.Get(i)
	}
	logDebug(logPrefix, "length of msg: ", len(msg))

	// get the connection associated with the specified connection ID
	plugin.connectionsMutex.RLock()
	connection, ok := plugin.connections[connectionId]
	plugin.connectionsMutex.RUnlock()
	if !ok {
		logError(logPrefix, "failed to find connection with ID = ", connectionId)
		plugin.sdk.OnPackageStatusChanged(handle, commsShims.PACKAGE_FAILED_GENERIC, commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	if _, err := (*connection).Write(msg); err != nil {
		plugin.sdk.OnPackageStatusChanged(handle, commsShims.PACKAGE_FAILED_GENERIC, commsShims.GetRACE_BLOCKING())
		return commsShims.PLUGIN_ERROR
	}

	plugin.sdk.OnPackageStatusChanged(handle, commsShims.PACKAGE_SENT, commsShims.GetRACE_BLOCKING())
	return commsShims.PLUGIN_OK
}

func (plugin *RacebirdPlugin) OpenConnection(handle uint64, linkType commsShims.LinkType, linkId string, link_hints string, send_timeout int) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("OpenConnection: (handle: %v, linkId: %v): ", handle, linkId)
	logDebug(logPrefix, "called")
	logDebug(logPrefix, "   type = ", linkType)
	logDebug(logPrefix, "   Link ID = ", linkId)
	logDebug(logPrefix, "   link_hints = ", link_hints)
	logDebug(logPrefix, "   send_timeout = ", send_timeout)
	defer logDebug(logPrefix, "returned")

	newConnectionId := plugin.sdk.GenerateConnectionId(linkId)
	plugin.linkConnectionCount[linkId] += 1
	logDebug(logPrefix, "opening new connection with ID: ", newConnectionId)

	linkProperties := plugin.linkProperties[linkId] // Needed for link status callback
	logDebug(logPrefix, "   linkproperties:", linkProperties)
	linkAdress := plugin.linkAddresses[linkId] // Get parsed link address info
	logDebug(logPrefix, "linkAdress:", linkAdress)

	isLoader := plugin.linkIsLoader[linkId]

	var obfsConn net.Conn = nil

	if isLoader {
		// Handle loaded / client-side link
		logDebug("OpenConnection:opening connection for LOADING link linkAdress: ", linkId)
		args := make(pt.Args)
		logDebug(logPrefix, "add certArg: ")
		args.Add(certArg, linkAdress.Cert)
		logDebug(logPrefix, "add iatArg: ")
		args.Add(iatArg, linkAdress.Iat)
		logDebug(logPrefix, "set tcpAddr: ")
		tcpAddr := linkAdress.Addr

		logDebug(logPrefix, "factory: ")
		factory, err := transports.Get(CHANNEL_GID).ClientFactory("")
		if err != nil {
			logDebug("transports.Get(obfs4).ClientFactory err: ", err)
		}
		obfs4Args, _ := factory.ParseArgs(&args)

		dialFn := net.Dial
		logDebug(logPrefix, "dialing with: ", tcpAddr, dialFn)
		obfsConn, err = factory.Dial("tcp", tcpAddr, dialFn, obfs4Args)

		// Add the connection to the Plugin's list of all active connections
		plugin.connectionsMutex.Lock()
		plugin.connections[newConnectionId] = &obfsConn
		plugin.connectionsMutex.Unlock()
	} else {
		// Handle created / server-side link
		// Check if link already has a running listener socket
		plugin.connectionsMutex.RLock()
		logDebug(logPrefix, "checking existing socket")
		if plugin.listenerSockets[linkId] == nil {
			logDebug(logPrefix, "starting listen")
			newListener, err := net.Listen(
				CONN_TYPE,
				linkAdress.Addr)
			if err != nil {
				logError("OpenConnection failed to create listener socket: ", err)
				plugin.sdk.OnConnectionStatusChanged(handle,
					"",
					commsShims.CONNECTION_CLOSED,
					commsShims.NewLinkProperties(),
					commsShims.GetRACE_BLOCKING())
				return commsShims.PLUGIN_ERROR
			}
			logDebug(logPrefix, "appending listener")
			plugin.listenerSockets[linkId] = &newListener
		}
		logDebug(logPrefix, "using existing listener")
		listener := plugin.listenerSockets[linkId]
		plugin.connectionsMutex.RUnlock()

		go func() {
			// Launch an Accept thread and return
			logDebug(logPrefix, "calling accept listener")
			logDebug(logPrefix, "listener?", listener)
			conn, err := (*listener).Accept()
			if err != nil {
				logError("OpenConnection failed to accept: ", err)
				plugin.sdk.OnConnectionStatusChanged(handle,
					"",
					commsShims.CONNECTION_CLOSED,
					commsShims.NewLinkProperties(),
					commsShims.GetRACE_BLOCKING())
			}
			logDebug(logPrefix, "accepted: ", conn)
			obfsConn, err := plugin.serverFactories[linkId].WrapConn(conn)
			if err != nil {
				logError("Handshake failed: ", err)
				plugin.sdk.OnConnectionStatusChanged(handle,
					"",
					commsShims.CONNECTION_CLOSED,
					commsShims.NewLinkProperties(),
					commsShims.GetRACE_BLOCKING())
			}

			// Add the connection to the Plugin's list of all active connections
			plugin.connectionsMutex.Lock()
			plugin.connections[newConnectionId] = &obfsConn
			plugin.connectionsMutex.Unlock()

			// Update the SDK about the connection being open
			// Start a listener (in a new goroutine) if the Link Type allows receipt of messages
			if linkType == commsShims.LT_RECV || linkType == commsShims.LT_BIDI {
				go plugin.connectionMonitor(&obfsConn, newConnectionId)
			}

			logDebug("Calling OnConnectionStatusChanged: ",
				handle, " ",
				newConnectionId, " ",
				commsShims.CONNECTION_OPEN, " ",
				linkProperties, " ",
				commsShims.GetRACE_BLOCKING())
			plugin.sdk.OnConnectionStatusChanged(handle, newConnectionId, commsShims.CONNECTION_OPEN, linkProperties, commsShims.GetRACE_BLOCKING())
		}()
		return commsShims.PLUGIN_OK
	}

	// Start a listener (in a new goroutine) if the Link Type allows receipt of messages
	if linkType == commsShims.LT_RECV || linkType == commsShims.LT_BIDI {
		go plugin.connectionMonitor(&obfsConn, newConnectionId)
	}

	logDebug("Calling OnConnectionStatusChanged: ",
		handle, " ",
		newConnectionId, " ",
		commsShims.CONNECTION_OPEN, " ",
		linkProperties, " ",
		commsShims.GetRACE_BLOCKING())
	plugin.sdk.OnConnectionStatusChanged(handle, newConnectionId, commsShims.CONNECTION_OPEN, linkProperties, commsShims.GetRACE_BLOCKING())

	// Return success
	return commsShims.PLUGIN_OK

}

// Close a connection with a given ID.
func (plugin *RacebirdPlugin) CloseConnection(handle uint64, connectionId string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("CloseConnection: (handle: %v, connectionId: %v): ", handle, connectionId)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	plugin.connectionsMutex.Lock()
	defer plugin.connectionsMutex.Unlock()
	if connection, ok := plugin.connections[connectionId]; ok {
		logDebug(logPrefix, "closing connection with ID ", connectionId)

		// Clean up internal connection details
		delete(plugin.connections, connectionId)
		linkId := linkIdFromConnectionId(connectionId)
		logDebug(logPrefix, "count of remaining connections on link: ", plugin.linkConnectionCount[linkId])
		plugin.linkConnectionCount[linkId] -= 1
		logDebug(logPrefix, "count of remaining connections on link: ", plugin.linkConnectionCount[linkId])
		(*connection).Close()
		// If the last connection on a created link is closed, close the listener socket as well
		if plugin.linkConnectionCount[linkIdFromConnectionId(connectionId)] == 0 && plugin.listenerSockets[linkId] != nil {
			logDebug(logPrefix, "Last open connection, closing listen socket")
			(*plugin.listenerSockets[linkId]).Close()
			delete(plugin.listenerSockets, linkId)
		}

		// Update the SDK that the connection has been closed
		plugin.sdk.OnConnectionStatusChanged(handle, connectionId, commsShims.CONNECTION_CLOSED, plugin.linkProperties[linkId], commsShims.GetRACE_BLOCKING())
	} else {
		logError("CloseConnection:unable to find connection with ID = ", connectionId)
		return commsShims.PLUGIN_ERROR
	}

	// Return success to the SDK
	return commsShims.PLUGIN_OK
}

func (plugin *RacebirdPlugin) DestroyLink(handle uint64, linkId string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("DestroyLink: (handle: %v, link ID: %v): ", handle, linkId)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")
	if _, ok := plugin.linkProperties[linkId]; !ok {
		logDebug(logPrefix, "unknown link ID")
		return commsShims.PLUGIN_ERROR
	}
	if plugin.linkConnectionCount[linkId] > 0 {
		logError(logPrefix, "refusing to destroy link with remaining connections (should call closeConnection first)")
		return commsShims.PLUGIN_ERROR
	}

	plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_DESTROYED, plugin.linkProperties[linkId], commsShims.GetRACE_BLOCKING())
	delete(plugin.linkAddresses, linkId)
	delete(plugin.linkProperties, linkId)
	delete(plugin.linkIsLoader, linkId)
	// Only _necessary_ for created links
	delete(plugin.serverFactories, linkId)

	return commsShims.PLUGIN_OK
}

func certIatFromBridgeFile(stateDir string) (string, string) {
	fPath := path.Join(stateDir, "obfs4_bridgeline.txt")
	data, err := ioutil.ReadFile(fPath)
	if err != nil {
		logError("Could not find ", fPath)
	}
	certExpr := regexp.MustCompile(`cert=([^ ]+)`)
	iatExpr := regexp.MustCompile(`iat-mode=([^ ]+)`)
	certMatch := certExpr.FindStringSubmatch(string(data))
	iatMatch := iatExpr.FindStringSubmatch(string(data))
	if len(certMatch) > 1 && len(iatMatch) > 1 {
		cert := certMatch[1]
		iatMode := strings.TrimRight(iatMatch[1], "\n ")
		return cert, iatMode
	} else {
		logError("Could not find cert in bridgeline file: ", data)
		return "", ""
	}
}

func (plugin *RacebirdPlugin) CreateLinkHelper(handle uint64, channelGid string, port string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("CreateLinkHelper: (handle: %v, channel: %v, port %v): ", handle, channelGid, port)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	if plugin.hostname == "" {
		logError(logPrefix, "Hostname parameter has not been provided, but is required for Creating links (i.e. acting as the server)")
		return commsShims.PLUGIN_ERROR
	}

	linkId := plugin.sdk.GenerateLinkId(channelGid)
	linkProps := plugin.getDefaultLinkProperties()

	// Make pt.Args object
	logDebug(logPrefix, "constructing args")
	ptArgs := make(pt.Args)
	if plugin.obfsParams[privateKeyArg] != "" {
		ptArgs.Add(privateKeyArg, plugin.obfsParams[privateKeyArg])
	}
	if plugin.obfsParams[iatArg] != "" {
		ptArgs.Add(iatArg, plugin.obfsParams[iatArg])
	}
	if plugin.obfsParams[nodeIDArg] != "" {
		ptArgs.Add(nodeIDArg, plugin.obfsParams[nodeIDArg])
	}
	if plugin.obfsParams[seedArg] != "" {
		ptArgs.Add(seedArg, plugin.obfsParams[seedArg])
	}

	// If <stateDir>/<stateFile> does not exist then they are created and all args are generated
	factory, err := transports.Get(CHANNEL_GID).ServerFactory("/tmp", &ptArgs)
	if err != nil {
		logError(logPrefix, "Error creating ServerFactory")
	}
	plugin.serverFactories[linkId] = factory
	obfs4Cert, iatMode := certIatFromBridgeFile("/tmp")
	addrString := plugin.hostname + ":" + port
	linkAdress := linkAddress{
		Addr: addrString,
		Cert: obfs4Cert,
		Iat:  iatMode,
	}
	plugin.linkAddresses[linkId] = linkAdress
	linkAddressBytes, _ := json.Marshal(linkAdress)
	linkAddressStr := string(linkAddressBytes)
	logInfo("Created Link at Address: ", linkAddressStr)
	linkProps.SetLinkAddress(linkAddressStr)
	plugin.linkProperties[linkId] = linkProps
	plugin.linkIsLoader[linkId] = false // used to determine how we handle the subsequent openConnection call
	plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_CREATED, linkProps, commsShims.GetRACE_BLOCKING())
	plugin.sdk.UpdateLinkProperties(linkId, linkProps, commsShims.GetRACE_BLOCKING())

	return commsShims.PLUGIN_OK

}

func (plugin *RacebirdPlugin) CreateLink(handle uint64, channelGid string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("CreateLink: (handle: %v, channel: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	addrString := strconv.Itoa(plugin.nextAvailablePort)
	plugin.nextAvailablePort += 1
	status := plugin.CreateLinkHelper(handle, channelGid, addrString)
	return status
}

func (plugin *RacebirdPlugin) CreateLinkFromAddress(handle uint64, channelGid string, linkAddressStr string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("CreateLinkFromAddress: (handle: %v, channel CHANNEL_GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	// TODO
	// Validate each element of the linkAddress against plugin vars:
	// extract nodeID and Public Key from linkAddress.Cert
	// check linkAddress.Addr matches hostname
	var linkAdress linkAddress
	err := json.Unmarshal([]byte(linkAddressStr), &linkAdress)
	if err != nil {
		logError(logPrefix, "link address failed to parse: ", linkAddressStr)
		return commsShims.PLUGIN_ERROR
	}
	port := strings.Split(linkAdress.Addr, ":")[1]
	status := plugin.CreateLinkHelper(handle, channelGid, port)

	return status
}

func (plugin *RacebirdPlugin) getDefaultLinkProperties() commsShims.LinkProperties {
	props := commsShims.NewLinkProperties()
	channelProps := plugin.sdk.GetChannelProperties(CHANNEL_GID)
	props.SetTransmissionType(channelProps.GetTransmissionType())
	props.SetConnectionType(channelProps.GetConnectionType())
	props.SetSendType(channelProps.GetSendType())
	props.SetReliable(channelProps.GetReliable())
	props.SetIsFlushable(channelProps.GetIsFlushable())
	props.SetDuration_s(channelProps.GetDuration_s())
	props.SetPeriod_s(channelProps.GetPeriod_s())
	props.SetMtu(channelProps.GetMtu())
	props.SetLinkType(commsShims.LT_BIDI)
	props.SetWorst(channelProps.GetCreatorExpected())
	props.SetExpected(channelProps.GetCreatorExpected())
	props.SetBest(channelProps.GetCreatorExpected())
	props.SetSupported_hints(channelProps.GetSupported_hints())
	props.SetChannelGid(CHANNEL_GID)
	return props
}

func (plugin *RacebirdPlugin) LoadLinkAddress(handle uint64, channelGid string, linkAddressStr string) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("LoadLinkAddress: (handle: %v, channel CHANNEL_GID: %v): ", handle, channelGid)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	// Setup RACE-side things:
	// Get a LinkID (the way the SDK will identify this link)
	// Get/Set LinkProperties (info the SDK will use to decide how to use this link)
	linkId := plugin.sdk.GenerateLinkId(channelGid)
	linkProps := plugin.getDefaultLinkProperties()
	linkProps.SetLinkAddress(linkAddressStr)
	logDebug(logPrefix, "Loading obfs4 link with ID: ", linkId)

	var linkAdress linkAddress
	err := json.Unmarshal([]byte(linkAddressStr), &linkAdress)
	logDebug(logPrefix, "Unmarshaled address to linkAdress:", linkAdress)
	if err != nil {
		logError(logPrefix, "Link Address did not parse: ", linkAddressStr)
		plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
	}

	logDebug(logPrefix, "Assigning ")
	// Update internal record keeping
	plugin.linkAddresses[linkId] = linkAdress
	plugin.linkProperties[linkId] = linkProps
	plugin.linkIsLoader[linkId] = true // used to determine how we handle the subsequent openConnection call

	// Callbacks to the SDK to tell it the link is ready-to-go
	plugin.sdk.OnLinkStatusChanged(handle, linkId, commsShims.LINK_LOADED, linkProps, commsShims.GetRACE_BLOCKING())
	plugin.sdk.UpdateLinkProperties(linkId, linkProps, commsShims.GetRACE_BLOCKING())

	// NOTE: we don't actually _do_ anything until the OpenConnection call
	logDebug(logPrefix, "Loaded racebird link with link address: ", linkAddressStr)

	return commsShims.PLUGIN_OK
}

func (plugin *RacebirdPlugin) LoadLinkAddresses(handle uint64, channelGid string, linkAddressStrs commsShims.StringVector) commsShims.PluginResponse {
	logPrefix := fmt.Sprintf("LoadLinkAddress: (handle: %v, channel CHANNEL_GID: %v): ", handle, channelGid)
	logError(logPrefix, "API not supported")
	plugin.sdk.OnLinkStatusChanged(handle, "", commsShims.LINK_DESTROYED, commsShims.NewLinkProperties(), commsShims.GetRACE_BLOCKING())
	return commsShims.PLUGIN_ERROR
}

func (plugin *RacebirdPlugin) FlushChannel(handle uint64, channelGid string, batchId uint64) commsShims.PluginResponse {
	logError("FlushChannel: plugin does not support flushing")
	return commsShims.PLUGIN_ERROR
}

func (plugin *RacebirdPlugin) OnUserAcknowledgementReceived(handle uint64) commsShims.PluginResponse {
	return commsShims.PLUGIN_OK
}

func linkIdFromConnectionId(connectionId string) string {
	return connectionId[:strings.LastIndex(connectionId, "/")]
}

func (plugin *RacebirdPlugin) connectionMonitor(conn *net.Conn, connectionId string) {
	logPrefix := fmt.Sprintf("connectionMonitor: (connectionId: %v): ", connectionId)
	logDebug(logPrefix, "called")
	defer logDebug(logPrefix, "returned")

	for true {
		// Read a length header to ensure receipt of full packages
		length_bytes := make([]byte, FRAME_HEADER_SIZE)
		logDebug(logPrefix, "reading length from conn ", conn)
		_, err := io.ReadFull(*conn, length_bytes[:])
		length := binary.BigEndian.Uint64(length_bytes)
		logDebug(logPrefix, "read length ", length_bytes)
		if err != nil {
			logDebug("Connection read error, assuming connection has been closed: ", err)
			plugin.CloseConnection(
				commsShims.GetNULL_RACE_HANDLE(),
				connectionId)
			return
		}

		// Read the length-designated number of bytes
		logDebug(logPrefix, "reading ", length, " bytes")
		data := make([]byte, length)
		_, err = io.ReadFull(*conn, data[:])
		if err != nil && err != io.EOF {
			logError(logPrefix, "Problem reading data from socket: ", err)
			return
		}
		if err == io.EOF {
			logError("Failed to read full packet. Trying anyway")
		}
		logDebug(logPrefix, "Read ", len(data), " byte message")

		// Irritating explicit copy from []byte to SWIG ByteVector
		rawData := commsShims.NewByteVector()
		for _, b := range data {
			rawData.Add(b)
		}

		// Construct the Raceboat EncPkg type from the data
		receivedEncPkg := commsShims.NewEncPkg(rawData)

		connectionIds := commsShims.NewStringVector()
		connectionIds.Add(connectionId)
		// Push package up to the SDK
		logDebug(logPrefix, "calling ReceiveEncPkg")
		sdkResponse := plugin.sdk.ReceiveEncPkg(receivedEncPkg, connectionIds, commsShims.GetRACE_BLOCKING())
		if sdkResponse.GetStatus() != commsShims.SDK_OK {
			logError("Failed sending encPkg for connections ",
				connectionIds.Get(0),
				" to the SDK: ",
				sdkResponse.GetStatus())
		}
		logDebug(logPrefix, "cleaning up")

		commsShims.DeleteByteVector(rawData)
		commsShims.DeleteEncPkg(receivedEncPkg)
	}
}

var plugin *RacebirdPlugin = nil

func InitRacebirdPlugin(sdk uintptr) {
	logDebug("InitRacebirdPlugin: called")
	defer logDebug("InitRacebirdPlugin: returned")
	if plugin != nil {
		logWarning("Trying to construct a new Golang plugin when one has been created already")
		return
	}

	plugin = &RacebirdPlugin{}
	plugin.sdk = commsShims.SwigcptrIRaceSdkComms(sdk)

}

//export CreateRacebirdPlugin
func CreateRacebirdPlugin(sdk uintptr) {
	logDebug("CreateRacebirdPlugin: called")
	InitRacebirdPlugin(sdk)
	logDebug("CreateRacebirdPlugin: returned")
}

//export DestroyRacebirdPlugin
func DestroyRacebirdPlugin() {
	logDebug("DestroyRacebirdPlugin: called")
	if plugin != nil {
		plugin = nil
	}
	logDebug("DestroyRacebirdPlugin: returned")
}

// For some reason, commsShims.PluginResponse, etc. are not recognized as exportable types
type PluginResponse int
type LinkType int

// Swig didn't bother to export this function, so here it is, copied straight from
// commsPluginBindingsGolang.go all its glory (or should I say... gory). We need this
// in order to properly free memory allocated by C++.
type swig_gostring struct {
	p uintptr
	n int
}

func swigCopyString(s string) string {
	p := *(*swig_gostring)(unsafe.Pointer(&s))
	r := string((*[0x7fffffff]byte)(unsafe.Pointer(p.p))[:p.n])
	commsShims.Swig_free(p.p)
	return r
}

//export RacebirdPluginInit
func RacebirdPluginInit(pluginConfig uintptr) PluginResponse {
	return PluginResponse(plugin.Init(commsShims.SwigcptrPluginConfig(pluginConfig)))
}

//export RacebirdPluginShutdown
func RacebirdPluginShutdown() PluginResponse {
	return PluginResponse(plugin.Shutdown())
}

//export RacebirdPluginSendPackage
func RacebirdPluginSendPackage(handle uint64, connectionId string, encPkg uintptr, timeoutTimestamp float64, batchId uint64) PluginResponse {
	return PluginResponse(plugin.SendPackage(handle, swigCopyString(connectionId), commsShims.SwigcptrEncPkg(encPkg), timeoutTimestamp, batchId))
}

//export RacebirdPluginOpenConnection
func RacebirdPluginOpenConnection(handle uint64, linkType LinkType, linkId string, link_hints string, send_timeout int) PluginResponse {
	var response = PluginResponse(plugin.OpenConnection(handle, commsShims.LinkType(linkType), swigCopyString(linkId), link_hints, send_timeout))
	logDebug("RacebirdPluginOpenConnection response", response)
	return response
}

//export RacebirdPluginCloseConnection
func RacebirdPluginCloseConnection(handle uint64, connectionId string) PluginResponse {
	return PluginResponse(plugin.CloseConnection(handle, swigCopyString(connectionId)))
}

//export RacebirdPluginDestroyLink
func RacebirdPluginDestroyLink(handle uint64, linkId string) PluginResponse {
	return PluginResponse(plugin.DestroyLink(handle, swigCopyString(linkId)))
}

//export RacebirdPluginCreateLink
func RacebirdPluginCreateLink(handle uint64, channelGid string) PluginResponse {
	return PluginResponse(plugin.CreateLink(handle, swigCopyString(channelGid)))
}

//export RacebirdPluginCreateLinkFromAddress
func RacebirdPluginCreateLinkFromAddress(handle uint64, channelGid string, linkAddress string) PluginResponse {
	return PluginResponse(plugin.CreateLinkFromAddress(handle, swigCopyString(channelGid), swigCopyString(linkAddress)))
}

//export RacebirdPluginLoadLinkAddress
func RacebirdPluginLoadLinkAddress(handle uint64, channelGid string, linkAddress string) PluginResponse {
	return PluginResponse(plugin.LoadLinkAddress(handle, swigCopyString(channelGid), swigCopyString(linkAddress)))
}

//export RacebirdPluginLoadLinkAddresses
func RacebirdPluginLoadLinkAddresses(handle uint64, channelGid string, linkAddresses uintptr) PluginResponse {
	return PluginResponse(plugin.LoadLinkAddresses(handle, swigCopyString(channelGid), commsShims.SwigcptrStringVector(linkAddresses)))
}

//export RacebirdPluginDeactivateChannel
func RacebirdPluginDeactivateChannel(handle uint64, channelGid string) PluginResponse {
	return PluginResponse(plugin.DeactivateChannel(handle, swigCopyString(channelGid)))
}

//export RacebirdPluginActivateChannel
func RacebirdPluginActivateChannel(handle uint64, channelGid string, roleName string) PluginResponse {
	return PluginResponse(plugin.ActivateChannel(handle, swigCopyString(channelGid), swigCopyString(roleName)))
}

//export RacebirdPluginOnUserInputReceived
func RacebirdPluginOnUserInputReceived(handle uint64, answered bool, response string) PluginResponse {
	return PluginResponse(plugin.OnUserInputReceived(handle, answered, swigCopyString(response)))
}

//export RacebirdPluginFlushChannel
func RacebirdPluginFlushChannel(handle uint64, connId string, batchId uint64) PluginResponse {
	return PluginResponse(plugin.FlushChannel(handle, swigCopyString(connId), batchId))
}

//export RacebirdPluginOnUserAcknowledgementReceived
func RacebirdPluginOnUserAcknowledgementReceived(handle uint64) PluginResponse {
	return PluginResponse(plugin.OnUserAcknowledgementReceived(handle))
}

func main() {}
