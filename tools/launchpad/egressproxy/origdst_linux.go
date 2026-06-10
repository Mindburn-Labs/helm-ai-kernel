//go:build linux

package main

import (
	"net"
	"strconv"
	"syscall"
)

// soOriginalDst is the SO_ORIGINAL_DST socket option from
// <linux/netfilter_ipv4.h>. After an iptables REDIRECT, conntrack remembers the
// pre-DNAT destination and exposes it here.
const soOriginalDst = 80

// originalDst recovers the original (pre-REDIRECT) destination of an intercepted
// connection via getsockopt(SO_ORIGINAL_DST). IPv4 only — the launchpad egress
// path does not use IPv6.
func originalDst(conn *net.TCPConn) (string, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return "", err
	}
	var addr string
	var soErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		mreq, e := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if e != nil {
			soErr = e
			return
		}
		// The returned blob is a sockaddr_in: sin_family(2) sin_port(2, network
		// byte order) sin_addr(4), laid into the Multiaddr field.
		b := mreq.Multiaddr
		ip := net.IPv4(b[4], b[5], b[6], b[7])
		port := int(b[2])<<8 | int(b[3])
		addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	})
	if ctrlErr != nil {
		return "", ctrlErr
	}
	if soErr != nil {
		return "", soErr
	}
	return addr, nil
}
