//go:build !(android || linux)
// +build !android,!linux

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

import "sync/atomic"

// tcpSpeedOptimizationsEnabled is a process-wide flag, set from
// Config.EnableTCPOptimizations. TCP socket tuning is currently implemented
// for Linux/Android only; other platforms retain default socket options.
var tcpSpeedOptimizationsEnabled atomic.Bool

// applyTCPSpeedOptimizations is a no-op on this platform.
func applyTCPSpeedOptimizations(_ int) {
}
