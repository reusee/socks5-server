package main

import (
	"flag"
	"github.com/reusee/socks5hs"
	"net"
	"sync"
	"time"
)

var (
	listenAddr string
)

func init() {
	flag.StringVar(&listenAddr, "listen", ":10800", "listen address")
	flag.Parse()
}

func main() {
	ln, err := net.Listen("tcp", listenAddr)
	ce(err, "listen")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	var closeConnOnce sync.Once
	closeConn := func() {
		closeConnOnce.Do(func() {
			conn.Close()
		})
	}

	addr, err := socks5hs.Handshake(conn)
	if err != nil {
		closeConn()
		return
	}

	targetConn, err := net.DialTimeout("tcp", addr, time.Second*16)
	if err != nil {
		closeConn()
		return
	}
	var closeTargetConnOnce sync.Once
	closeTargetConn := func() {
		closeTargetConnOnce.Do(func() {
			targetConn.Close()
		})
	}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				closeConn()
				break
			}
			_, err = targetConn.Write(buf[:n])
			if err != nil {
				closeTargetConn()
				break
			}
		}
	}()

	buf := make([]byte, 1024)
	for {
		n, err := targetConn.Read(buf)
		if err != nil {
			closeTargetConn()
			break
		}
		_, err = conn.Write(buf[:n])
		if err != nil {
			closeConn()
			break
		}
	}
}
