import Foundation
import Testing
@testable import OpenClaw

struct JarvisDirectoryTests {
    @Test func `Jarvis stable ids match the manual gateway ids`() {
        #expect(JarvisGatewayRoute.stableID(host: "abc123-s.deyaochen.com") ==
            GatewayConnectionController.ManualAuthOverride.manualStableID(host: "abc123-s.deyaochen.com", port: 443))
    }

    @Test func `saved Access headers are what a gateway connection sends`() {
        let stableID = JarvisGatewayRoute.stableID(host: "jarvistest-s.deyaochen.com")
        let service = "dev.de0ch.openclaw.tests.custom-headers"
        let token = JarvisDeviceToken(id: "d", clientId: "cid.access", clientSecret: "secret", pairedAt: Date())
        #expect(GatewaySettingsStore.saveGatewayCustomHeaders(
            token.accessHeaders, gatewayStableID: stableID, service: service))
        #expect(GatewaySettingsStore.loadGatewayCustomHeaders(gatewayStableID: stableID, service: service) ==
            token.accessHeaders)
        _ = GatewaySettingsStore.clearGatewayCustomHeaders(gatewayStableID: stableID, service: service)
    }

    @Test @MainActor func `web views take only the Access cookie from a response`() throws {
        let url = try #require(URL(string: "https://abc123-s.deyaochen.com/"))
        let response = try #require(HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
            "Set-Cookie": "CF_Authorization=jwt.value; Path=/; Secure; HttpOnly; SameSite=None",
        ]))
        let cookies = JarvisWebAccess.cookies(from: response, for: url)
        #expect(cookies.map(\.name) == ["CF_Authorization"])
        #expect(cookies.first?.domain == "abc123-s.deyaochen.com")
        #expect(JarvisWebAccess.headers(for: try #require(URL(string: "https://example.com/"))) == nil)
    }
}
