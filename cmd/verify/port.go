package main

import "net"

// listen reserves an ephemeral TCP port for the restart test instance.
func listen() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
