//go:build android || linux
// +build android linux

/*
 * Copyright (c) 2025, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// tcpSpeedOptimizationsEnabled is a process-wide flag, set from
// Config.EnableTCPOptimizations, which activates client-side TCP
// performance tuning in dial socket control callbacks.
var tcpSpeedOptimizationsEnabled atomic.Bool

// tcpOptimizationCCNames lists congestion control algorithms to try, in
// order of preference. BBR substantially outperforms CUBIC on lossy,
// high-latency paths; kernels without BBR (or without the module loaded)
// leave the default algorithm untouched.
var tcpOptimizationCCNames = []string{"bbr", "bbr2", "bbr3"}

// tcpOptimizationSocketBufferBytes is the target SO_RCVBUF/SO_SNDBUF size
// for optimized sockets. Larger buffers sustain higher throughput over
// high-RTT paths (the kernel typically doubles the requested value and
// caps it by net.core.{r,w}mem_max).
const tcpOptimizationSocketBufferBytes = 4 * 1024 * 1024

// applyTCPSpeedOptimizations applies best-effort TCP performance options to
// a socket file descriptor. All options are advisory: unsupported values
// (e.g. a congestion control algorithm not available in the kernel) are
// skipped without error, as the dial must proceed regardless.
func applyTCPSpeedOptimizations(socketFD int) {

	// Congestion control: try BBR variants; leave default otherwise.
	for _, cc := range tcpOptimizationCCNames {
		if unix.SetsockoptString(
			socketFD, unix.IPPROTO_TCP, unix.TCP_CONGESTION, cc) == nil {
			break
		}
	}

	// Socket buffers for high-BDP paths.
	_ = unix.SetsockoptInt(
		socketFD, unix.SOL_SOCKET, unix.SO_RCVBUF, tcpOptimizationSocketBufferBytes)
	_ = unix.SetsockoptInt(
		socketFD, unix.SOL_SOCKET, unix.SO_SNDBUF, tcpOptimizationSocketBufferBytes)

	// Keepalive tuning: detect dead peers faster than the 2h default.
	_ = unix.SetsockoptInt(
		socketFD, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 60)
	_ = unix.SetsockoptInt(
		socketFD, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 20)
	_ = unix.SetsockoptInt(
		socketFD, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 5)
}
