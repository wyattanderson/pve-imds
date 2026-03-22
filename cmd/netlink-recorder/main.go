// netlink-recorder captures RTNLGRP_LINK netlink messages related to tap
// interface lifecycle events and writes them to a file as base64-encoded lines.
//
// Run this on a real Proxmox host while performing VM operations (start, stop,
// migrate, etc.), then copy the output file back to your development machine to
// use as a fixture for unit and integration tests.
//
// Usage:
//
//	netlink-recorder [-output capture.nl] [-filter tap]
//
// Each line of the output file is the base64-encoded Data field of one
// netlink.Message. Lines are written in the order they are received. You can
// manually add, remove, or reorder lines to construct specific test scenarios.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mdlayher/netlink"
)

// Linux RTNETLINK constants not exposed by the netlink package.
const (
	rtmNewLink = 16
	rtmDelLink = 17
	iflaIfname = 3
)

// ifInfomsg is the fixed-size header that precedes netlink attributes in
// RTM_NEWLINK / RTM_DELLINK messages (struct ifinfomsg in linux/rtnetlink.h).
type ifInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

func main() {
	outputPath := flag.String("output", "capture.nl", "file to write captured messages to (one base64-encoded message per line)")
	filterPrefix := flag.String("filter", "tap", "only record messages for interfaces whose name starts with this prefix (empty = record all)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logger.Info("opening output file", "path", *outputPath)
	f, err := os.OpenFile(*outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		logger.Error("failed to open output file", "path", *outputPath, "err", err)
		os.Exit(1)
	}
	defer f.Close() //nolint:errcheck

	logger.Info("dialing netlink RTNETLINK socket")
	// family 0 = NETLINK_ROUTE
	conn, err := netlink.Dial(0, nil)
	if err != nil {
		logger.Error("failed to dial netlink", "err", err)
		os.Exit(1)
	}
	// RTNLGRP_LINK = 1
	logger.Info("joining RTNLGRP_LINK multicast group")
	if err := conn.JoinGroup(1); err != nil {
		logger.Error("failed to join RTNLGRP_LINK", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Close the connection when the context is cancelled so that conn.Receive()
	// unblocks immediately rather than waiting for the next packet.
	go func() {
		<-ctx.Done()
		logger.Debug("context cancelled, closing netlink connection")
		conn.Close() //nolint:errcheck
	}()

	logger.Info("recording netlink messages",
		"output", *outputPath,
		"filter", *filterPrefix,
		"tip", "perform VM operations now; press Ctrl-C to stop",
	)

	recorded := 0
	skipped := 0

	for {
		msgs, err := conn.Receive()
		if err != nil {
			// conn.Close() from the goroutine above causes Receive to return an
			// error; if the context is done that's the expected shutdown path.
			if ctx.Err() != nil {
				logger.Info("shutting down", "recorded", recorded, "skipped", skipped)
				return
			}
			logger.Error("receive error", "err", err)
			continue
		}

		logger.Info("received messages", "count", len(msgs))

		for _, msg := range msgs {
			ifname, msgType := parseMessage(msg)

			if *filterPrefix != "" && !strings.HasPrefix(ifname, *filterPrefix) {
				logger.Debug("skipping message",
					"type", msgType,
					"ifname", ifname,
					"reason", "does not match filter prefix",
					"filter", *filterPrefix,
				)
				skipped++
				continue
			}

			recorded++
			logger.Info("recording message",
				"line", recorded,
				"type", msgType,
				"ifname", ifname,
				"data_bytes", len(msg.Data),
			)

			raw, err := msg.MarshalBinary()
			if err != nil {
				logger.Error("failed to marshal message", "err", err)
				os.Exit(1)
			}
			encoded := base64.StdEncoding.EncodeToString(raw)
			if _, err := fmt.Fprintln(f, encoded); err != nil {
				logger.Error("failed to write message", "err", err)
				os.Exit(1)
			}
		}
	}
}

// parseMessage extracts the interface name and a human-readable message type
// from a raw netlink message. Returns empty strings if the message cannot be
// parsed (caller should still decide whether to record it).
func parseMessage(msg netlink.Message) (ifname, msgType string) {
	switch msg.Header.Type {
	case rtmNewLink:
		msgType = "RTM_NEWLINK"
	case rtmDelLink:
		msgType = "RTM_DELLINK"
	default:
		msgType = fmt.Sprintf("type_%d", msg.Header.Type)
	}

	hdrSize := binary.Size(ifInfomsg{})
	if len(msg.Data) < hdrSize {
		return "", msgType
	}

	var info ifInfomsg
	if err := binary.Read(bytes.NewReader(msg.Data[:hdrSize]), binary.LittleEndian, &info); err != nil {
		return "", msgType
	}

	attrs, err := netlink.NewAttributeDecoder(msg.Data[hdrSize:])
	if err != nil {
		return "", msgType
	}
	for attrs.Next() {
		if attrs.Type() == iflaIfname {
			ifname = attrs.String()
			break
		}
	}

	return ifname, msgType
}
