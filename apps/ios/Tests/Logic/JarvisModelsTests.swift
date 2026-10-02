import Foundation
import Testing

struct JarvisModelsTests {
    @Test func `parses a paired callback with the matching state`() throws {
        let url = try #require(URL(string:
            "openclaw-de0ch://paired?state=abcdefghijklmnop&id=dev1&clientId=cid.access&clientSecret=sec"))
        let now = Date(timeIntervalSince1970: 1000)
        let result = JarvisPairing.parseCallback(url, expectedState: "abcdefghijklmnop", now: now)
        #expect(result == .success(JarvisDeviceToken(
            id: "dev1", clientId: "cid.access", clientSecret: "sec", pairedAt: now)))
    }

    @Test func `rejects a callback whose state does not match`() throws {
        let url = try #require(URL(string: "openclaw-de0ch://paired?state=other&id=a&clientId=b&clientSecret=c"))
        #expect(JarvisPairing.parseCallback(url, expectedState: "abcdefghijklmnop") == .failure(.stateMismatch))
    }

    @Test func `reports a refusal with its status`() throws {
        let url = try #require(URL(string: "openclaw-de0ch://paired?state=s1&error=too_soon&status=429"))
        #expect(JarvisPairing.parseCallback(url, expectedState: "s1") ==
            .failure(.refused(error: "too_soon", status: 429)))
    }

    @Test func `rejects another scheme and an incomplete answer`() throws {
        let other = try #require(URL(string: "jarvis-app://paired?state=s1&id=a&clientId=b&clientSecret=c"))
        #expect(JarvisPairing.parseCallback(other, expectedState: "s1") == .failure(.wrongCallback))
        let partial = try #require(URL(string: "openclaw-de0ch://paired?state=s1&id=a&clientId=b"))
        #expect(JarvisPairing.parseCallback(partial, expectedState: "s1") == .failure(.incomplete))
    }

    @Test func `pair URL carries state name model and app`() throws {
        let url = try #require(JarvisPairing.pairURL(state: "s1", deviceName: "Deyao's iPhone", model: "iPhone18,1"))
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        #expect(url.host == "jarvis.deyaochen.com")
        #expect(url.path == "/api/devices/pair")
        #expect(items.first { $0.name == "app" }?.value == "openclaw")
        #expect(items.first { $0.name == "name" }?.value == "Deyao's iPhone")
        let state = JarvisPairing.makeState()
        #expect((16...64).contains(state.count))
        #expect(state.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
    }

    @Test func `refusal means an Access page or a non JSON 401 or 403`() throws {
        let access = try #require(URL(string: "https://de0ch.cloudflareaccess.com/cdn-cgi/access/login"))
        let jarvis = try #require(URL(string: "https://jarvis.deyaochen.com/api/remotes"))
        #expect(JarvisRefusal.isRefusal(finalURL: access, statusCode: 200, contentType: "text/html"))
        #expect(JarvisRefusal.isRefusal(finalURL: jarvis, statusCode: 403, contentType: "text/html"))
        #expect(!JarvisRefusal.isRefusal(finalURL: jarvis, statusCode: 403, contentType: "application/json"))
        #expect(!JarvisRefusal.isRefusal(finalURL: jarvis, statusCode: 500, contentType: nil))
        let token = JarvisDeviceToken(
            id: "d",
            clientId: "c",
            clientSecret: "s",
            pairedAt: Date(timeIntervalSince1970: 0))
        #expect(!JarvisRefusal.meansRevoked(token: token, now: Date(timeIntervalSince1970: 10)))
        #expect(JarvisRefusal.meansRevoked(token: token, now: Date(timeIntervalSince1970: 31)))
    }

    @Test func `decodes the remotes answer and only trusts session hosts`() throws {
        let json = """
        {"sessions":[
          {"id":"abc123","title":"Fix the router","state":"started","model":"claude-opus-5-5",
           "url":"wss://abc123-s.deyaochen.com","token":"gw-token"},
          {"id":"def456","title":null,"state":"paused","model":null,"url":null,"token":null},
          {"id":"evil1","title":"x","state":"started","url":"wss://evil.example.com","token":"t"},
          {"id":"odd","title":"y","state":"restoring","url":null,"token":null}
        ]}
        """
        let sessions = try JSONDecoder().decode(JarvisRemotesResponse.self, from: Data(json.utf8)).sessions
        #expect(sessions.count == 4)
        #expect(sessions[0].isConnectable)
        #expect(sessions[0].gatewayHost == "abc123-s.deyaochen.com")
        #expect(sessions[1].state == .paused)
        #expect(sessions[1].displayTitle == "def456")
        #expect(!sessions[2].isConnectable)
        #expect(sessions[3].state == .other)
        #expect(!JarvisGatewayRoute.isSessionHost("a.b-s.deyaochen.com"))
        #expect(!JarvisGatewayRoute.isSessionHost("-s.deyaochen.com"))
    }

    @Test func `sync plan upserts sessions and removes only gone Jarvis gateways`() {
        let started = JarvisRemote(
            id: "abc123",
            title: "One",
            state: .started,
            model: nil,
            url: "wss://abc123-s.deyaochen.com",
            token: "gw")
        let paused = JarvisRemote(id: "def456", title: "Two", state: .paused, model: nil, url: nil, token: nil)
        let previously = [
            "manual|abc123-s.deyaochen.com|443": "abc123",
            "manual|gone99-s.deyaochen.com|443": "gone99",
        ]
        let plan = JarvisSyncPlan.make(remotes: [started, paused], previouslyManaged: previously)
        #expect(plan.upserts == [
            .init(
                sessionID: "abc123",
                stableID: "manual|abc123-s.deyaochen.com|443",
                host: "abc123-s.deyaochen.com",
                name: "One",
                token: "gw",
                connect: true),
            .init(
                sessionID: "def456",
                stableID: "manual|def456-s.deyaochen.com|443",
                host: "def456-s.deyaochen.com",
                name: "Two",
                token: nil,
                connect: false),
        ])
        #expect(plan.removals == ["manual|gone99-s.deyaochen.com|443"])
        #expect(plan.managed.count == 2)
    }

    @Test func `device token headers are the two Access headers`() {
        let token = JarvisDeviceToken(id: "d", clientId: "cid", clientSecret: "sec", pairedAt: Date())
        #expect(token.accessHeaders == ["CF-Access-Client-Id": "cid", "CF-Access-Client-Secret": "sec"])
    }
}
