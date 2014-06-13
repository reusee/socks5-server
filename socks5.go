package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/reusee/closer"
	"github.com/reusee/signaler"
)

const (
	VERSION = byte(5)

	METHOD_NOT_REQUIRED  = byte(0)
	METHOD_NO_ACCEPTABLE = byte(0xff)

	RESERVED = byte(0)

	ADDR_TYPE_IP     = byte(1)
	ADDR_TYPE_IPV6   = byte(4)
	ADDR_TYPE_DOMAIN = byte(3)

	CMD_CONNECT       = byte(1)
	CMD_BIND          = byte(2)
	CMD_UDP_ASSOCIATE = byte(3)

	REP_SUCCEED                    = byte(0)
	REP_SERVER_FAILURE             = byte(1)
	REP_CONNECTION_NOT_ALLOW       = byte(2)
	REP_NETWORK_UNREACHABLE        = byte(3)
	REP_HOST_UNREACHABLE           = byte(4)
	REP_CONNECTION_REFUSED         = byte(5)
	REP_TTL_EXPIRED                = byte(6)
	REP_COMMAND_NOT_SUPPORTED      = byte(7)
	REP_ADDRESS_TYPE_NOT_SUPPORTED = byte(8)
)

type SocksServer struct {
	*signaler.Signaler
	closer.Closer
}

type SocksClientInfo struct {
	Conn     net.Conn
	HostPort string
}

func NewSocksServer(listenAddr string) (*SocksServer, error) {
	server := &SocksServer{
		Signaler: signaler.NewSignaler(),
		Closer:   closer.NewCloser(),
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	server.OnClose(func() {
		ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if server.IsClosing {
					return
				}
				continue
			}
			go server.handshake(conn)
		}
	}()
	return server, nil
}

func (self *SocksServer) handshake(conn net.Conn) {
	var ver, nMethods byte

	// handshake
	err := binary.Read(conn, binary.BigEndian, &ver)
	if err != nil {
		return
	}
	err = binary.Read(conn, binary.BigEndian, &nMethods)
	if err != nil {
		return
	}
	methods := make([]byte, nMethods)
	err = binary.Read(conn, binary.BigEndian, methods)
	if err != nil {
		return
	}
	err = binary.Write(conn, binary.BigEndian, VERSION)
	if err != nil {
		return
	}
	if ver != VERSION || nMethods < byte(1) {
		err = binary.Write(conn, binary.BigEndian, METHOD_NO_ACCEPTABLE)
		if err != nil {
			return
		}
	} else {
		if bytes.IndexByte(methods, METHOD_NOT_REQUIRED) == -1 {
			err = binary.Write(conn, binary.BigEndian, METHOD_NO_ACCEPTABLE)
			if err != nil {
				return
			}
		} else {
			err = binary.Write(conn, binary.BigEndian, METHOD_NOT_REQUIRED)
			if err != nil {
				return
			}
		}
	}

	// request
	var cmd, reserved, addrType byte
	err = binary.Read(conn, binary.BigEndian, &ver)
	if err != nil {
		return
	}
	err = binary.Read(conn, binary.BigEndian, &cmd)
	if err != nil {
		return
	}
	err = binary.Read(conn, binary.BigEndian, &reserved)
	if err != nil {
		return
	}
	err = binary.Read(conn, binary.BigEndian, &addrType)
	if err != nil {
		return
	}
	if ver != VERSION {
		return
	}
	if reserved != RESERVED {
		return
	}
	if addrType != ADDR_TYPE_IP && addrType != ADDR_TYPE_DOMAIN && addrType != ADDR_TYPE_IPV6 {
		writeAck(conn, REP_ADDRESS_TYPE_NOT_SUPPORTED)
		return
	}

	var address []byte
	if addrType == ADDR_TYPE_IP {
		address = make([]byte, 4)
	} else if addrType == ADDR_TYPE_DOMAIN {
		var domainLength byte
		err := binary.Read(conn, binary.BigEndian, &domainLength)
		if err != nil {
			return
		}
		address = make([]byte, domainLength)
	} else if addrType == ADDR_TYPE_IPV6 {
		address = make([]byte, 16)
	}
	err = binary.Read(conn, binary.BigEndian, address)
	if err != nil {
		return
	}
	var port uint16
	err = binary.Read(conn, binary.BigEndian, &port)
	if err != nil {
		return
	}

	var hostPort string
	if addrType == ADDR_TYPE_IP || addrType == ADDR_TYPE_IPV6 {
		ip := net.IP(address)
		hostPort = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	} else if addrType == ADDR_TYPE_DOMAIN {
		hostPort = net.JoinHostPort(string(address), strconv.Itoa(int(port)))
	}

	if cmd != CMD_CONNECT {
		writeAck(conn, REP_COMMAND_NOT_SUPPORTED)
		return
	}
	writeAck(conn, REP_SUCCEED)

	self.Signal("client", conn, hostPort)
}

func writeAck(conn net.Conn, reply byte) {
	err := binary.Write(conn, binary.BigEndian, VERSION)
	if err != nil {
		return
	}
	err = binary.Write(conn, binary.BigEndian, reply)
	if err != nil {
		return
	}
	err = binary.Write(conn, binary.BigEndian, RESERVED)
	if err != nil {
		return
	}
	err = binary.Write(conn, binary.BigEndian, ADDR_TYPE_IP)
	if err != nil {
		return
	}
	err = binary.Write(conn, binary.BigEndian, [4]byte{0, 0, 0, 0})
	if err != nil {
		return
	}
	err = binary.Write(conn, binary.BigEndian, uint16(0))
	if err != nil {
		return
	}
}
