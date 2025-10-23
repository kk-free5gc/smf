package handler_test

import (
    "bytes"
    "io"
    "net"
    "testing"

	"github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/free5gc/pfcp"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/internal/pfcp/handler"
)

type LogCapture struct {
	buffer bytes.Buffer
}

func (lc *LogCapture) Write(p []byte) (n int, err error) {
	return lc.buffer.Write(p)
}

func (lc *LogCapture) String() string {
	return lc.buffer.String()
}

// func TestHandlePfcpHeartbeatRequest(t *testing.T) {
// }

func TestHandlePfcpManagementRequest(t *testing.T) {
    Convey("Logs unimplemented warning", t, func() {
        remoteAddr := &net.UDPAddr{}
        testPfcpReq := &pfcp.Message{}
        msg := pfcpUdp.NewMessage(remoteAddr, testPfcpReq)
        logCapture := &LogCapture{}
        logger.Log.SetOutput(io.MultiWriter(logCapture, logrus.StandardLogger().Out))
        handler.HandlePfcpPfdManagementRequest(msg)

        So(logCapture.String(), ShouldContainSubstring, "PFCP PFD Management Request handling is not implemented")
    })
}

func TestHandlePfcpAssociationSetupRequest(t *testing.T) {
    Convey("NodeID is nil logs error", t, func() {
        remoteAddr := &net.UDPAddr{
            IP:   net.ParseIP("192.168.1.1"),
            Port: 12345,
        }

		testPfcpReq := &pfcp.Message{
			Header: pfcp.Header{
				Version:         1,
				MP:              0,
				S:               0,
				MessageType:     pfcp.PFCP_ASSOCIATION_SETUP_REQUEST,
				MessageLength:   9,
				SEID:            0,
				SequenceNumber:  1,
				MessagePriority: 0,
			},
			Body: pfcp.PFCPAssociationSetupRequest{
				NodeID: nil,
			},
		}

        logCapture := &LogCapture{}
        logger.Log.SetOutput(io.MultiWriter(logCapture, logrus.StandardLogger().Out))

        msg := pfcpUdp.NewMessage(remoteAddr, testPfcpReq)
        handler.HandlePfcpAssociationSetupRequest(msg)

        So(logCapture.String(), ShouldContainSubstring, "pfcp association needs NodeID")
    })
    Convey("NodeID set, UPF not found", t, func() {
        remoteAddr := &net.UDPAddr{
            IP:   net.ParseIP("192.168.1.1"),
            Port: 12345,
        }

		testPfcpReq := &pfcp.Message{
			Header: pfcp.Header{
				Version:         1,
				MP:              0,
				S:               0,
				MessageType:     pfcp.PFCP_ASSOCIATION_SETUP_REQUEST,
				MessageLength:   9,
				SEID:            0,
				SequenceNumber:  1,
				MessagePriority: 0,
			},
			Body: pfcp.PFCPAssociationSetupRequest{
				NodeID: &pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv4Address,
					IP:         net.ParseIP("192.168.1.1").To4(),
				},
			},
		}

        logCapture := &LogCapture{}
        logger.Log.SetOutput(io.MultiWriter(logCapture, logrus.StandardLogger().Out))

        msg := pfcpUdp.NewMessage(remoteAddr, testPfcpReq)
        handler.HandlePfcpAssociationSetupRequest(msg)

        So(logCapture.String(), ShouldContainSubstring, "Handle PFCP Association Setup Request with NodeID[192.168.1.1]")
        So(logCapture.String(), ShouldContainSubstring, "can't find UPF[192.168.1.1]")
    })
}

func TestHandlePfcpAssociationUpdateRequest(t *testing.T) {
    Convey("Logs unimplemented warning", t, func() {
        remoteAddr := &net.UDPAddr{}
        testPfcpReq := &pfcp.Message{}
        msg := pfcpUdp.NewMessage(remoteAddr, testPfcpReq)
        logCapture := &LogCapture{}
        logger.Log.SetOutput(io.MultiWriter(logCapture, logrus.StandardLogger().Out))
        handler.HandlePfcpAssociationUpdateRequest(msg)

        So(logCapture.String(), ShouldContainSubstring, "PFCP Association Update Request handling is not implemented")
    })
}

// func TestHandlePfcpAssociationReleaseRequest(t *testing.T) {
// }
