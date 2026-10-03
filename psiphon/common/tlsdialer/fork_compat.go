/*
 * Copyright (c) 2026, Psiphon Inc.
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

package tlsdialer

// This file contains fork-local exported wrappers around helpers that live in
// dialer.go. They are needed because the psiphon package implements the
// fork's fronted-meek CDN scan feature (psiphon/frontedMeekCDNScan.go and
// psiphon/dialParameters.go) and the supported VerifyServerNames/ALPNProtocols
// TLS behavior. Upstream relocated these helpers from package psiphon
// (psiphon/tlsDialer.go) into this package, where they are unexported.
//
// Keeping the wrappers in this separate file minimizes merge conflicts with
// upstream changes to dialer.go.

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	utls "github.com/Psiphon-Labs/utls"
)

// GetUTLSClientHelloID exposes getUTLSClientHelloID to the psiphon package.
func GetUTLSClientHelloID(
	p parameters.ParametersAccessor,
	tlsProfile string) (utls.ClientHelloID, *utls.ClientHelloSpec, error) {

	return getUTLSClientHelloID(p, tlsProfile)
}

// GetClientHelloVersion exposes getClientHelloVersion to the psiphon package.
func GetClientHelloVersion(
	utlsClientHelloID utls.ClientHelloID,
	utlsClientHelloSpec *utls.ClientHelloSpec) (string, error) {

	return getClientHelloVersion(utlsClientHelloID, utlsClientHelloSpec)
}

// MakeVerifyServerNames exposes makeVerifyServerNames to the psiphon package.
func MakeVerifyServerNames(
	verifyServerName string,
	verifyServerNames []string) []string {

	return makeVerifyServerNames(verifyServerName, verifyServerNames)
}
