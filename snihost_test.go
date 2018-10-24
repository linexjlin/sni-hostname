package snihost

import (
	"fmt"
	"net"
	"testing"
)

func TestParseSNIHost(t *testing.T) {
	l, err := net.Listen("tcp4", ":8443")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(c.RemoteAddr())
		hostname, bodydata := ParseSNIHost(c)
		fmt.Println("host:", hostname, bodydata)
	}
}
