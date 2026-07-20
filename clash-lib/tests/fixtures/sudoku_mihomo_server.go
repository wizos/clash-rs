// This fixture is intentionally built from the Mihomo module under test rather
// than duplicating its HTTP-mask implementation. Run it with the Mihomo module
// root as the working directory.
package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/metacubex/mihomo/transport/sudoku"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/httpmask"
)

func main() {
	if len(os.Args) != 5 {
		panic("usage: sudoku_mihomo_server STACK MODE PATH_ROOT AUTH_KEY")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	if os.Args[1] == "tunnel" {
		serveTunnel(listener, os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if os.Args[1] == "full" {
		serveSudoku(listener, os.Args[2], os.Args[3])
		return
	}
	panic("STACK must be tunnel or full")
}

func serveTunnel(listener net.Listener, mode, pathRoot, authKey string) {
	server := httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
		Mode:     mode,
		PathRoot: pathRoot,
		AuthKey:  authKey,
	})
	fmt.Println(listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			result, tunnel, err := server.HandleConn(conn)
			if err != nil {
				_ = conn.Close()
				return
			}
			if result == httpmask.HandleStartTunnel && tunnel != nil {
				go func() {
					_, _ = io.Copy(tunnel, tunnel)
					_ = tunnel.Close()
				}()
			}
		}()
	}
}

func serveSudoku(listener net.Listener, mode, pathRoot string) {
	privateKey, publicKey, err := sudoku.GenKeyPair()
	if err != nil {
		panic(err)
	}
	tables, err := sudoku.NewServerTablesWithCustomPatterns(
		sudoku.ServerAEADSeed(publicKey),
		"prefer_entropy",
		"",
		nil,
	)
	if err != nil {
		panic(err)
	}
	cfg := sudoku.DefaultConfig()
	cfg.Key = publicKey
	cfg.AEADMethod = "chacha20-poly1305"
	cfg.Tables = tables
	cfg.HTTPMaskMode = mode
	cfg.HTTPMaskPathRoot = pathRoot
	cfg.DisableHTTPMask = false
	tunnelServer := sudoku.NewHTTPMaskTunnelServer(cfg)
	fmt.Printf("%s %s\n", listener.Addr().String(), privateKey)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			handshakeConn, handshakeCfg, done, err := tunnelServer.WrapConn(conn)
			if err != nil || done {
				_ = conn.Close()
				return
			}
			protocolConn, meta, err := sudoku.ServerHandshake(handshakeConn, handshakeCfg)
			if err != nil {
				_ = handshakeConn.Close()
				return
			}
			session, err := sudoku.ReadServerSession(protocolConn, meta)
			if err != nil {
				_ = protocolConn.Close()
				return
			}
			_, _ = io.Copy(session.Conn, session.Conn)
			_ = session.Conn.Close()
		}()
	}
}
