package proxy

import (
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"

	"github.com/xvzc/SpoofDPI/packet"
)

func (pxy *Proxy) handleHttp(lConn *net.TCPConn, pkt *packet.HttpPacket, ip string) {
	pkt.Tidy()

	// Create a connection to the requested server
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1081", nil, proxy.Direct)
	if err != nil {
		log.Debug("[HTTPS] Error creating SOCKS5 dialer: ", err)
		return
	}

	// Используем диалер для установления соединения
	tcpConn, err := dialer.Dial("tcp", ip+":"+pkt.Port())
	if err != nil {
		lConn.Close()
		log.Debug("[HTTPS] ", err)
		return
	}

	rConn, ok := tcpConn.(*net.TCPConn)
	if !ok {
		log.Debug("Connection is not TCP")
		return
	}

	defer func() {
		lConn.Close()
		log.Debug("[HTTP] Closing client Connection.. ", lConn.RemoteAddr())

		rConn.Close()
		log.Debug("[HTTP] Closing server Connection.. ", pkt.Domain(), " ", rConn.LocalAddr())
	}()

	log.Debug("[HTTP] New connection to the server ", pkt.Domain(), " ", rConn.LocalAddr())

	go Serve(rConn, lConn, "[HTTP]", lConn.RemoteAddr().String(), pkt.Domain(), pxy.timeout)

	_, err = rConn.Write(pkt.Raw())
	if err != nil {
		log.Debug("[HTTP] Error sending request to ", pkt.Domain(), err)
		return
	}

	log.Debug("[HTTP] Sent a request to ", pkt.Domain())

	Serve(lConn, rConn, "[HTTP]", lConn.RemoteAddr().String(), pkt.Domain(), pxy.timeout)
}
