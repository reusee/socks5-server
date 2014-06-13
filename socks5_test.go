package socks5

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	server, err := New("0.0.0.0:33333")
	if err != nil {
		t.Fatal(err)
	}
	server.OnSignal("client", func(args ...interface{}) {
		conn := args[0].(net.Conn)
		hostPort := args[1].(string)
		fmt.Printf("%v %v\n", conn, hostPort)
	})
	time.Sleep(time.Hour)
}
