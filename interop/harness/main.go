// Command harness drives yggdrasil-go for yggdrasil-rs's interop tests.
//
//	harness vectors
//	    Answers JSON requests on stdin, one per line, about addresses, link
//	    handshakes, multicast beacons, ICMPv6, nodeinfo and configuration.
//	harness node -seed HEX [-listen URI] [-password P]
//	    Runs a node with an IPv6 packet interface, controlled over stdin.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/hjson/hjson-go/v4"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: harness vectors | harness node ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "vectors":
		runVectors()
	case "node":
		runNode(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}

func mustHex(s string) []byte {
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bs
}

/***********
 * vectors *
 ***********/

type request struct {
	Op       string          `json:"op"`
	Key      string          `json:"key"`
	Data     string          `json:"data"`
	Seed     string          `json:"seed"`
	Password string          `json:"password"`
	Major    uint16          `json:"major"`
	Minor    uint16          `json:"minor"`
	Priority uint8           `json:"priority"`
	Port     uint16          `json:"port"`
	Hash     string          `json:"hash"`
	MTU      int             `json:"mtu"`
	Text     string          `json:"text"`
	Privacy  bool            `json:"privacy"`
	NodeInfo json.RawMessage `json:"nodeinfo"`
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func answer(req request) any {
	switch req.Op {
	case "address":
		key := ed25519.PublicKey(mustHex(req.Key))
		addr := address.AddrForKey(key)
		snet := address.SubnetForKey(key)
		return map[string]string{
			"address":     hex.EncodeToString(addr[:]),
			"subnet":      hex.EncodeToString(snet[:]),
			"address_key": hex.EncodeToString(addr.GetKey()),
			"subnet_key":  hex.EncodeToString(snet.GetKey()),
			"text":        net.IP(addr[:]).String(),
		}

	case "address_key":
		var addr address.Address
		copy(addr[:], mustHex(req.Data))
		var snet address.Subnet
		copy(snet[:], addr[:8])
		return map[string]any{
			"address_key":   hex.EncodeToString(addr.GetKey()),
			"subnet_key":    hex.EncodeToString(snet.GetKey()),
			"address_valid": addr.IsValid(),
			"subnet_valid":  snet.IsValid(),
		}

	case "meta_encode":
		secret := ed25519.NewKeyFromSeed(mustHex(req.Seed))
		bs, err := core.ExportEncodeMetadata(req.Major, req.Minor, req.Priority, secret, []byte(req.Password))
		return map[string]string{"data": hex.EncodeToString(bs), "error": errorString(err)}

	case "meta_decode":
		m, err := core.ExportDecodeMetadata(mustHex(req.Data), []byte(req.Password))
		return map[string]any{
			"major":    m.Major,
			"minor":    m.Minor,
			"key":      hex.EncodeToString(m.Key),
			"priority": m.Priority,
			"error":    errorString(err),
		}

	case "adv_encode":
		bs := multicast.ExportEncodeAdvertisement(req.Major, req.Minor, mustHex(req.Key), req.Port, mustHex(req.Hash))
		return map[string]string{"data": hex.EncodeToString(bs)}

	case "adv_decode":
		major, minor, key, port, hash, err := multicast.ExportDecodeAdvertisement(mustHex(req.Data))
		return map[string]any{
			"major": major,
			"minor": minor,
			"key":   hex.EncodeToString(key),
			"port":  port,
			"hash":  hex.EncodeToString(hash),
			"error": errorString(err),
		}

	case "icmp_ptb":
		// What ipv6rwc sends back for a packet over the MTU
		bs := mustHex(req.Data)
		buf := make([]byte, 512)
		cn := copy(buf, bs)
		ptb := &icmp.PacketTooBig{MTU: req.MTU, Data: buf[:cn]}
		packet, err := ipv6rwc.CreateICMPv6(buf[8:24], buf[24:40], ipv6.ICMPTypePacketTooBig, 0, ptb)
		return map[string]string{"data": hex.EncodeToString(packet), "error": errorString(err)}

	case "config":
		cfg := config.GenerateConfig()
		if _, err := cfg.ReadFrom(strings.NewReader(req.Text)); err != nil {
			return map[string]string{"error": err.Error()}
		}
		cfg.AdminListen = ""
		js, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		hj, err := hjson.Marshal(cfg)
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		pem, err := cfg.MarshalPEMPrivateKey()
		if err != nil {
			return map[string]string{"error": err.Error()}
		}
		nodeinfo, err := core.ExportNodeInfo(cfg.NodeInfo, true)
		return map[string]string{
			"json":     string(js),
			"hjson":    string(hj),
			"pem":      string(pem),
			"nodeinfo": string(nodeinfo),
			"error":    errorString(err),
		}

	default:
		return map[string]string{"error": "unknown op " + req.Op}
	}
}

func runVectors() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			panic(err)
		}
		bs, err := json.Marshal(answer(req))
		if err != nil {
			panic(err)
		}
		out.Write(bs)
		out.WriteByte('\n')
		out.Flush()
	}
}

/********
 * node *
 ********/

type logger struct{}

func (logger) Printf(string, ...any) {}
func (logger) Println(...any)        {}
func (logger) Infof(string, ...any)  {}
func (logger) Infoln(...any)         {}
func (logger) Warnf(string, ...any)  {}
func (logger) Warnln(...any)         {}
func (logger) Errorf(string, ...any) {}
func (logger) Errorln(...any)        {}
func (logger) Debugf(string, ...any) {}
func (logger) Debugln(...any)        {}
func (logger) Traceln(...any)        {}

// A node that sends and receives IPv6 packets with no next header (59),
// carrying the test payload directly after the IPv6 header.
func runNode(args []string) {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	seed := fs.String("seed", "", "hex private key seed")
	listen := fs.String("listen", "", "listener URI")
	password := fs.String("password", "", "group password")
	nodeinfo := fs.String("nodeinfo", "", "nodeinfo JSON")
	_ = fs.Parse(args)

	cfg := config.GenerateConfig()
	cfg.PrivateKey = config.KeyBytes(ed25519.NewKeyFromSeed(mustHex(*seed)))
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		panic(err)
	}
	options := []core.SetupOption{core.GroupPassword(*password)}
	if *nodeinfo != "" {
		var info map[string]any
		if err := json.Unmarshal([]byte(*nodeinfo), &info); err != nil {
			panic(err)
		}
		options = append(options, core.NodeInfo(info))
	}
	c, err := core.New(cfg.Certificate, logger{}, options...)
	if err != nil {
		panic(err)
	}
	listenAddr := "-"
	if *listen != "" {
		u, err := url.Parse(*listen)
		if err != nil {
			panic(err)
		}
		l, err := c.Listen(u, "")
		if err != nil {
			panic(err)
		}
		listenAddr = l.Addr().String()
	}
	rwc := ipv6rwc.NewReadWriteCloser(c)
	rwc.SetMTU(rwc.MaxMTU())
	var outMutex sync.Mutex
	say := func(format string, args ...any) {
		outMutex.Lock()
		defer outMutex.Unlock()
		fmt.Printf(format+"\n", args...)
	}
	addr := rwc.Address()
	snet := rwc.Subnet()
	say("ready %s %s %s %s", hex.EncodeToString(c.PublicKey()), net.IP(addr[:]), net.IP(append(snet[:], 0, 0, 0, 0, 0, 0, 0, 1)), listenAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := rwc.Read(buf)
			if err != nil {
				return
			}
			packet := buf[:n]
			say("recv %s %s %s", net.IP(packet[8:24]), net.IP(packet[24:40]), hex.EncodeToString(packet[40:]))
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "peer":
			u, err := url.Parse(fields[1])
			if err == nil {
				err = c.AddPeer(u, "")
			}
			say("peered %s", errorString(err))
		case "send":
			// send SRC DST PAYLOAD
			src, dst := net.ParseIP(fields[1]), net.ParseIP(fields[2])
			payload := mustHex(fields[3])
			packet := make([]byte, 40, 40+len(payload))
			packet[0] = 0x60
			packet[4] = byte(len(payload) >> 8)
			packet[5] = byte(len(payload))
			packet[6] = 59
			packet[7] = 64
			copy(packet[8:24], src.To16())
			copy(packet[24:40], dst.To16())
			packet = append(packet, payload...)
			_, err := rwc.Write(packet)
			say("sent %s", errorString(err))
		case "quit":
			c.Stop()
			return
		}
	}
	c.Stop()
}
