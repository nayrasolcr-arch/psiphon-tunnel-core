package psiphon

import (
        "encoding/binary"
        "net/netip"
        "strings"
        "testing"
        "time"

        "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
        "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestFrontedMeekCDNScanBuiltInCandidateSetsValidate(t *testing.T) {

        names := make(map[string]struct{})
        for _, candidateSet := range frontedMeekCDNScanBuiltInCandidateSets {
                if candidateSet.name == "" {
                        t.Fatal("empty built-in candidate set name")
                }
                if _, ok := names[candidateSet.name]; ok {
                        t.Fatalf("duplicate built-in candidate set name: %s", candidateSet.name)
                }
                names[candidateSet.name] = struct{}{}

                if err := candidateSet.spec.Validate(); err != nil {
                        t.Fatalf("invalid built-in candidate set %s: %v", candidateSet.name, err)
                }
                if candidateSet.spec.CandidateCount() == 0 {
                        t.Fatalf("empty built-in candidate set: %s", candidateSet.name)
                }
                testFrontedMeekCDNScanBuiltInIPCandidatesNotCovered(
                        t,
                        candidateSet.name,
                        candidateSet.spec.IPCandidates)
        }
}

func TestFrontedMeekCDNScanBuiltInIncludesCuratedAdditions(t *testing.T) {

        expectedPriorityOrder := []string{
                "built-in-legacy-android-overrides",
                "built-in-curated-fronting",
                "built-in-psiphon-akamai",
                "built-in-fastly",
                "built-in-psiphon-bunny",
        }
        for i, expectedName := range expectedPriorityOrder {
                if frontedMeekCDNScanBuiltInCandidateSets[i].name != expectedName {
                        t.Fatalf(
                                "unexpected built-in priority at %d: %s",
                                i,
                                frontedMeekCDNScanBuiltInCandidateSets[i].name)
                }
        }

        if !testFrontedMeekCDNScanStringSliceContains(
                frontedMeekCDNScanBuiltInLegacyAndroidOverrideIPCandidates,
                "92.123.102.43") {
                t.Fatal("missing legacy Android CDN edge IP candidate")
        }
        if !testFrontedMeekCDNScanStringSliceContains(
                frontedMeekCDNScanBuiltInLegacyAndroidOverrideSNIServerNames,
                "a248.e.akamai.net") {
                t.Fatal("missing legacy Android CDN edge SNI candidate")
        }

        if len(frontedMeekCDNScanBuiltInCuratedIPCandidates) != 95 {
                t.Fatalf(
                        "unexpected curated IP candidate count: %d",
                        len(frontedMeekCDNScanBuiltInCuratedIPCandidates))
        }
        if len(frontedMeekCDNScanBuiltInCuratedSNIServerNames) != 15 {
                t.Fatalf(
                        "unexpected curated SNI candidate count: %d",
                        len(frontedMeekCDNScanBuiltInCuratedSNIServerNames))
        }

        for _, ipAddress := range []string{
                "2.16.221.37",
                "151.101.128.223",
                "185.200.232.50",
        } {
                if !testFrontedMeekCDNScanStringSliceContains(
                        frontedMeekCDNScanBuiltInCuratedIPCandidates,
                        ipAddress) {
                        t.Fatalf("missing curated IP candidate: %s", ipAddress)
                }
        }

        for _, sniServerName := range []string{
                "bbe-getimage.akamaized.net",
                "prod.global.ssl.fastly.net",
                "b-cdn.net",
        } {
                if !testFrontedMeekCDNScanStringSliceContains(
                        frontedMeekCDNScanBuiltInCuratedSNIServerNames,
                        sniServerName) {
                        t.Fatalf("missing curated SNI candidate: %s", sniServerName)
                }
        }

        for _, testCase := range []struct {
                name   string
                values []string
                value  string
        }{
                {
                        name:   "akamai",
                        values: frontedMeekCDNScanBuiltInAkamaiSNIServerNames,
                        value:  "bbe-getimage.akamaized.net",
                },
                {
                        name:   "fastly",
                        values: frontedMeekCDNScanBuiltInFastlySNIServerNames,
                        value:  "prod.global.ssl.fastly.net",
                },
                {
                        name:   "fastly",
                        values: frontedMeekCDNScanBuiltInFastlySNIServerNames,
                        value:  "quic.map.fastly.net",
                },
                {
                        name:   "google",
                        values: frontedMeekCDNScanBuiltInGoogleSNIServerNames,
                        value:  "google.com",
                },
        } {
                if !testFrontedMeekCDNScanStringSliceContains(
                        testCase.values,
                        testCase.value) {
                        t.Fatalf(
                                "missing %s SNI candidate: %s",
                                testCase.name,
                                testCase.value)
                }
        }

        for _, excludedIPAddress := range []string{
                "5.160.13.85",
                "37.191.95.70",
                "78.39.234.140",
                "80.191.243.226",
                "185.208.174.167",
        } {
                if testFrontedMeekCDNScanStringSliceContains(
                        frontedMeekCDNScanBuiltInCuratedIPCandidates,
                        excludedIPAddress) {
                        t.Fatalf("unexpected curated IP candidate: %s", excludedIPAddress)
                }
        }
}

func TestFrontedMeekCDNScanSelectionPriority(t *testing.T) {

        originalBuiltInCandidateSets := frontedMeekCDNScanBuiltInCandidateSets
        defer func() {
                frontedMeekCDNScanBuiltInCandidateSets = originalBuiltInCandidateSets
        }()

        frontedMeekCDNScanBuiltInCandidateSets = []frontedMeekCDNScanCandidateSet{
                {
                        name: "test-built-in",
                        spec: parameters.FrontedMeekCDNScanSpec{
                                IPCandidates:   []string{"198.51.100.1"},
                                SNIServerNames: []string{"built-in.example.com"},
                        },
                },
        }

        params, err := parameters.NewParameters(nil)
        if err != nil {
                t.Fatalf("parameters.NewParameters failed: %v", err)
        }

        _, err = params.Set("", 0, map[string]interface{}{
                parameters.FrontedMeekCDNScanSpecParameter: parameters.FrontedMeekCDNScanSpec{
                        IPCandidates:   []string{"192.0.2.1"},
                        SNIServerNames: []string{"user.example.com"},
                },
                parameters.FrontedMeekCDNScanUseBuiltInSpec: true,
                parameters.FrontedMeekDialOverrides: parameters.FrontedMeekDialOverrideSpecs{
                        &parameters.FrontedMeekDialOverride{
                                OverrideID:                     "test-override",
                                MatchFrontingProviderIDRegexes: []string{"test-provider"},
                                DialAddresses:                  []string{"203.0.113.1"},
                                SNIServerName:                  "override.example.com",
                        },
                },
        })
        if err != nil {
                t.Fatalf("params.Set failed: %v", err)
        }

        override, scanCandidate, _, ok, err := selectFrontedMeekCDNScanOverride(
                params.Get(),
                "test-network",
                "test-provider",
                []string{"front.example.com"},
                "host.example.com",
                0)
        if err != nil || !ok {
                t.Fatalf("select user candidate failed: ok=%t err=%v", ok, err)
        }
        if override.DialAddress != "192.0.2.1" ||
                scanCandidate == nil ||
                scanCandidate.IPAddress != "192.0.2.1" {
                t.Fatalf("unexpected first candidate: override=%+v scan=%+v", override, scanCandidate)
        }

        override, scanCandidate, _, ok, err = selectFrontedMeekCDNScanOverride(
                params.Get(),
                "test-network",
                "test-provider",
                []string{"front.example.com"},
                "host.example.com",
                2)
        if err != nil || !ok {
                t.Fatalf("select override candidate failed: ok=%t err=%v", ok, err)
        }
        if override.DialAddress != "203.0.113.1" || scanCandidate != nil {
                t.Fatalf("unexpected override candidate: override=%+v scan=%+v", override, scanCandidate)
        }

        override, scanCandidate, _, ok, err = selectFrontedMeekCDNScanOverride(
                params.Get(),
                "test-network",
                "test-provider",
                []string{"front.example.com"},
                "host.example.com",
                3)
        if err != nil || !ok {
                t.Fatalf("select built-in candidate failed: ok=%t err=%v", ok, err)
        }
        if override.DialAddress != "198.51.100.1" ||
                scanCandidate == nil ||
                scanCandidate.IPAddress != "198.51.100.1" {
                t.Fatalf("unexpected built-in candidate: override=%+v scan=%+v", override, scanCandidate)
        }
}

func TestFrontedMeekCDNScanPreservesOverrideWrapping(t *testing.T) {

        params, err := parameters.NewParameters(nil)
        if err != nil {
                t.Fatalf("parameters.NewParameters failed: %v", err)
        }

        _, err = params.Set("", 0, map[string]interface{}{
                parameters.FrontedMeekDialOverrides: parameters.FrontedMeekDialOverrideSpecs{
                        &parameters.FrontedMeekDialOverride{
                                OverrideID:                     "test-override",
                                MatchFrontingProviderIDRegexes: []string{"test-provider"},
                                DialAddresses:                  []string{"203.0.113.1"},
                                SNIServerName:                  "override.example.com",
                        },
                },
        })
        if err != nil {
                t.Fatalf("params.Set failed: %v", err)
        }

        override, scanCandidate, _, ok, err := selectFrontedMeekCDNScanOverride(
                params.Get(),
                "test-network",
                "test-provider",
                []string{"front.example.com"},
                "host.example.com",
                3)
        if err != nil || !ok {
                t.Fatalf("select wrapped override candidate failed: ok=%t err=%v", ok, err)
        }
        if override.DialAddress != "203.0.113.1" || scanCandidate != nil {
                t.Fatalf("unexpected wrapped override candidate: override=%+v scan=%+v", override, scanCandidate)
        }
}

func TestFrontedMeekCDNScanRecordResultDoesNotEmitFoundNotice(t *testing.T) {

        foundNoticeCount := 0
        err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
                noticeType, payload, err := GetNotice(notice)
                if err != nil {
                        t.Errorf("GetNotice failed: %v", err)
                        return
                }
                message, _ := payload["message"].(string)
                if noticeType == "Info" && strings.HasPrefix(message, "cdn fronting scan found") {
                        foundNoticeCount += 1
                }
        }))
        if err != nil {
                t.Fatalf("SetNoticeWriter failed: %v", err)
        }
        defer ResetNoticeWriter()

        state := &frontedMeekCDNScanState{
                datastoreKey: "test-fronted-meek-cdn-scan-found-notice",
                entries:      make(map[string]*frontedMeekCDNScanCacheEntry),
        }

        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.1",
                SNIServerName: "one.example.com",
        }, true, 0)
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.1",
                SNIServerName: "one.example.com",
        }, true, 0)
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.2",
                SNIServerName: "two.example.com",
        }, true, 0)

        if foundNoticeCount != 0 {
                t.Fatalf("found notice count = %d, want 0", foundNoticeCount)
        }
}

func TestFrontedMeekCDNScanFoundNoticeFromDialParams(t *testing.T) {

        foundNoticeMessage := ""
        err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
                noticeType, payload, err := GetNotice(notice)
                if err != nil {
                        t.Errorf("GetNotice failed: %v", err)
                        return
                }
                message, _ := payload["message"].(string)
                if noticeType == "Info" && strings.HasPrefix(message, "cdn fronting scan found") {
                        foundNoticeMessage = message
                }
        }))
        if err != nil {
                t.Fatalf("SetNoticeWriter failed: %v", err)
        }
        defer ResetNoticeWriter()

        dialParams := &DialParameters{
                FrontedMeekCDNScanCandidate: true,
                MeekFrontingDialOverrideID:  frontedMeekCDNScanOverrideID,
                MeekFrontingDialAddress:     "192.0.2.4",
                MeekSNIServerName:           "",
                frontedMeekCDNScanSelectedCandidate: parameters.FrontedMeekCDNScanCandidate{
                        IPAddress:     "192.0.2.1",
                        SNIServerName: "selected.example.com",
                },
        }
        if !isFrontedMeekCDNScanDialParams(dialParams) {
                t.Fatalf("expected scan dial params to be detected as CDN scan dial params")
        }

        noticeFrontedMeekCDNScanConnected(dialParams)

        expectedMessage := "cdn fronting scan found (ip: 192\\.0\\.2\\.4, sni: none)"
        if foundNoticeMessage != expectedMessage {
                t.Fatalf("found notice message = %q, want %q", foundNoticeMessage, expectedMessage)
        }
}

func TestFrontedMeekCDNScanFoundNoticeFromReplayDialParams(t *testing.T) {

        foundNoticeMessage := ""
        err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
                noticeType, payload, err := GetNotice(notice)
                if err != nil {
                        t.Errorf("GetNotice failed: %v", err)
                        return
                }
                message, _ := payload["message"].(string)
                if noticeType == "Info" && strings.HasPrefix(message, "cdn fronting scan found") {
                        foundNoticeMessage = message
                }
        }))
        if err != nil {
                t.Fatalf("SetNoticeWriter failed: %v", err)
        }
        defer ResetNoticeWriter()

        dialParams := &DialParameters{
                MeekFrontingDialOverrideID: frontedMeekCDNScanOverrideID,
                MeekFrontingDialAddress:    "192.0.2.3",
                MeekSNIServerName:          "cached.example.com",
        }
        if !isFrontedMeekCDNScanDialParams(dialParams) {
                t.Fatalf("expected replay dial params to be detected as CDN scan dial params")
        }

        noticeFrontedMeekCDNScanConnected(dialParams)

        expectedMessage := "cdn fronting scan found (ip: 192\\.0\\.2\\.3, sni: cached.example.com)"
        if foundNoticeMessage != expectedMessage {
                t.Fatalf("found notice message = %q, want %q", foundNoticeMessage, expectedMessage)
        }
}

func TestFrontedMeekCDNScanFoundNoticeFromConnectedCDNProtocol(t *testing.T) {

        foundNoticeMessage := ""
        err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
                noticeType, payload, err := GetNotice(notice)
                if err != nil {
                        t.Errorf("GetNotice failed: %v", err)
                        return
                }
                message, _ := payload["message"].(string)
                if noticeType == "Info" && strings.HasPrefix(message, "cdn fronting scan found") {
                        foundNoticeMessage = message
                }
        }))
        if err != nil {
                t.Fatalf("SetNoticeWriter failed: %v", err)
        }
        defer ResetNoticeWriter()

        dialParams := &DialParameters{
                TunnelProtocol:          protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP_CDN,
                MeekFrontingDialAddress: "203.0.113.9",
                MeekSNIServerName:       "",
        }
        if isFrontedMeekCDNScanDialParams(dialParams) {
                t.Fatalf("did not expect connected CDN protocol dial params to be scan-marked")
        }

        noticeFrontedMeekCDNScanConnected(dialParams)

        expectedMessage := "cdn fronting scan found (ip: 203\\.0\\.113\\.9, sni: none)"
        if foundNoticeMessage != expectedMessage {
                t.Fatalf("found notice message = %q, want %q", foundNoticeMessage, expectedMessage)
        }
}

func testFrontedMeekCDNScanStringSliceContains(values []string, value string) bool {
        for _, candidate := range values {
                if candidate == value {
                        return true
                }
        }
        return false
}

func testFrontedMeekCDNScanBuiltInIPCandidatesNotCovered(
        t *testing.T,
        name string,
        candidates []string) {

        t.Helper()

        prefixes := make([]netip.Prefix, 0, len(candidates))
        for _, candidate := range candidates {
                prefix, err := netip.ParsePrefix(candidate)
                if err != nil {
                        addr, addrErr := netip.ParseAddr(candidate)
                        if addrErr != nil {
                                t.Fatalf("invalid built-in IP candidate %s in %s", candidate, name)
                        }
                        prefix = netip.PrefixFrom(addr, addr.BitLen())
                }
                prefixes = append(prefixes, prefix.Masked())
        }

        for i, prefix := range prefixes {
                for j, otherPrefix := range prefixes {
                        if i == j {
                                continue
                        }
                        if testFrontedMeekCDNScanPrefixContains(prefix, otherPrefix) {
                                t.Fatalf(
                                        "built-in IP candidate %s in %s is covered by %s",
                                        candidates[j],
                                        name,
                                        candidates[i])
                        }
                }
        }
}

func testFrontedMeekCDNScanPrefixContains(prefix, otherPrefix netip.Prefix) bool {
        return prefix.Contains(otherPrefix.Addr()) &&
                prefix.Contains(testFrontedMeekCDNScanPrefixLastAddr(otherPrefix))
}

func testFrontedMeekCDNScanPrefixLastAddr(prefix netip.Prefix) netip.Addr {
        addr := prefix.Addr()
        addrBytes := addr.As4()
        value := binary.BigEndian.Uint32(addrBytes[:])
        value += uint32((uint64(1) << (32 - uint(prefix.Bits()))) - 1)
        var lastBytes [4]byte
        binary.BigEndian.PutUint32(lastBytes[:], value)
        return netip.AddrFrom4(lastBytes)
}

func TestFrontedMeekCDNScanQualityOrdering(t *testing.T) {

        state := &frontedMeekCDNScanState{
                datastoreKey: "test-fronted-meek-cdn-scan-quality-ordering",
                entries:      make(map[string]*frontedMeekCDNScanCacheEntry),
        }

        // Fast edge: established in 1200ms.
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.10",
                SNIServerName: "fast.example.com",
        }, true, 1200)

        // Slow edge: established in 9000ms, recorded more recently.
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.30",
                SNIServerName: "slow.example.com",
        }, true, 9000)
        time.Sleep(10 * time.Millisecond)

        // Medium edge: established in 4000ms, most recent of all.
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.20",
                SNIServerName: "medium.example.com",
        }, true, 4000)

        // Unmeasured edge: success with no duration sample.
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.40",
                SNIServerName: "unknown.example.com",
        }, true, 0)

        candidates, skipped, _ := state.candidateHints()
        if len(candidates) != 4 {
                t.Fatalf("candidate count = %d, want 4", len(candidates))
        }
        if len(skipped) != 0 {
                t.Fatalf("skipped count = %d, want 0", len(skipped))
        }

        // The fast edge must be preferred over the more recent slow edge; the
        // unmeasured edge ranks with the medium bucket (bucket 1), so the
        // expected order is: fast, then medium and unknown (recency: unknown
        // was recorded last), then slow.
        expectOrder := []string{
                "fast.example.com",
                "unknown.example.com",
                "medium.example.com",
                "slow.example.com",
        }
        for i, want := range expectOrder {
                if candidates[i].SNIServerName != want {
                        t.Fatalf("candidate[%d] = %s, want %s (order: %v)",
                                i, candidates[i].SNIServerName, want, candidates)
                }
        }

        // Best duration must survive a later, slower success: re-dial the fast
        // edge with a slow result and confirm BestConnectDurationMs is kept.
        state.recordResult(parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.10",
                SNIServerName: "fast.example.com",
        }, true, 5000)
        entry := state.entries[parameters.FrontedMeekCDNScanCandidate{
                IPAddress:     "192.0.2.10",
                SNIServerName: "fast.example.com",
        }.Key()]
        if entry.BestConnectDurationMs != 1200 || entry.LastConnectDurationMs != 5000 {
                t.Fatalf("best/last = %d/%d, want 1200/5000",
                        entry.BestConnectDurationMs, entry.LastConnectDurationMs)
        }
}
