import Foundation

// DE0CH fork: Jarvis (jarvis.deyaochen.com, Deyao's self-hosted Claude cloud) lists every OpenClaw
// session it runs. The app pairs ONCE with Jarvis (a per-device Cloudflare Access service token) and
// then shows each session as a gateway. Pure value logic lives here so the logic tests can cover it.

enum JarvisConfig {
    static let baseURL = URL(string: "https://jarvis.deyaochen.com")!
    static let callbackScheme = "openclaw-de0ch"
    static let appName = "openclaw"
    static let sessionHostSuffix = "-s.deyaochen.com"
    /// A service token minted seconds ago is refused until Cloudflare propagates it (~5 s).
    static let freshTokenGrace: TimeInterval = 30
    static let accessHostSuffix = ".cloudflareaccess.com"
}

/// The per-device Access service token Jarvis minted at pairing. Every request to Jarvis and to a
/// session host carries it as the two CF-Access headers. Credentials: Keychain only, never logged.
struct JarvisDeviceToken: Codable, Equatable, Sendable {
    let id: String
    let clientId: String
    let clientSecret: String
    let pairedAt: Date

    var accessHeaders: [String: String] {
        ["CF-Access-Client-Id": self.clientId, "CF-Access-Client-Secret": self.clientSecret]
    }
}

enum JarvisPairingError: Error, Equatable, Sendable {
    case wrongCallback
    case stateMismatch
    case refused(error: String, status: Int?)
    case incomplete
    case cancelled
    case failed(String)

    var message: String {
        switch self {
        case .wrongCallback, .incomplete: "Jarvis sent an unexpected sign-in answer."
        case .stateMismatch: "The sign-in answer did not match this request. Try again."
        case let .refused(error, status):
            status == 429 ? "Jarvis just paired a device. Wait 30 seconds and try again."
                : "Jarvis refused the sign-in (\(error))."
        case .cancelled: "Sign-in cancelled."
        case let .failed(detail): detail
        }
    }
}

enum JarvisPairing {
    /// The nonce the app sends as `state` (Jarvis accepts 16–64 of [A-Za-z0-9_-]).
    static func makeState() -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: 0...255)
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func pairURL(state: String, deviceName: String, model: String) -> URL? {
        var components = URLComponents(
            url: JarvisConfig.baseURL.appendingPathComponent("api/devices/pair"),
            resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "name", value: deviceName),
            URLQueryItem(name: "model", value: model),
            URLQueryItem(name: "app", value: JarvisConfig.appName),
        ]
        return components?.url
    }

    /// `openclaw-de0ch://paired?state=…&id=…&clientId=…&clientSecret=…` or `…&error=…&status=…`.
    static func parseCallback(_ url: URL, expectedState: String, now: Date = Date())
        -> Result<JarvisDeviceToken, JarvisPairingError>
    {
        guard url.scheme?.lowercased() == JarvisConfig.callbackScheme,
              url.host?.lowercased() == "paired",
              let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        else { return .failure(.wrongCallback) }
        func value(_ name: String) -> String? {
            items.first(where: { $0.name == name })?.value.flatMap { $0.isEmpty ? nil : $0 }
        }
        guard value("state") == expectedState else { return .failure(.stateMismatch) }
        if let error = value("error") {
            return .failure(.refused(error: error, status: value("status").flatMap(Int.init)))
        }
        guard let id = value("id"), let clientId = value("clientId"), let clientSecret = value("clientSecret")
        else { return .failure(.incomplete) }
        return .success(JarvisDeviceToken(id: id, clientId: clientId, clientSecret: clientSecret, pairedAt: now))
    }
}

enum JarvisRefusal {
    /// Copied from the Jarvis app: a refusal = the request ENDED on *.cloudflareaccess.com (redirects
    /// followed), or a 401/403 whose body is not JSON (Access's own page, not a Jarvis error).
    static func isRefusal(finalURL: URL?, statusCode: Int, contentType: String?) -> Bool {
        if let host = finalURL?.host?.lowercased(), host.hasSuffix(JarvisConfig.accessHostSuffix) {
            return true
        }
        guard statusCode == 401 || statusCode == 403 else { return false }
        return !(contentType?.lowercased().contains("json") ?? false)
    }

    /// Within the grace window after pairing a refusal is Cloudflare propagation, not a revoke.
    static func meansRevoked(token: JarvisDeviceToken, now: Date = Date()) -> Bool {
        now.timeIntervalSince(token.pairedAt) > JarvisConfig.freshTokenGrace
    }
}

struct JarvisRemote: Codable, Equatable, Sendable, Identifiable {
    enum State: String, Codable, Sendable {
        case started
        case paused
        case other

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = State(rawValue: raw) ?? .other
        }
    }

    let id: String
    let title: String?
    let state: State
    let model: String?
    let url: String?
    let token: String?

    var displayTitle: String {
        let trimmed = self.title?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? self.id : trimmed
    }

    /// Only a session-host wss:// URL is accepted, so a bad answer can never point the
    /// device token's headers at another host.
    var gatewayHost: String? {
        guard let url, let components = URLComponents(string: url),
              components.scheme?.lowercased() == "wss",
              let host = components.host?.lowercased(),
              JarvisGatewayRoute.isSessionHost(host),
              components.port == nil || components.port == 443
        else { return nil }
        return host
    }

    var isConnectable: Bool {
        self.state == .started && self.gatewayHost != nil && !(self.token ?? "").isEmpty
    }
}

struct JarvisRemotesResponse: Codable, Sendable {
    let sessions: [JarvisRemote]
}

enum JarvisGatewayRoute {
    static let port = 443

    static func isSessionHost(_ host: String) -> Bool {
        let host = host.lowercased()
        return host.hasSuffix(JarvisConfig.sessionHostSuffix) && host.count > JarvisConfig.sessionHostSuffix.count &&
            !host.dropLast(JarvisConfig.sessionHostSuffix.count).contains(".")
    }

    static func host(sessionID: String) -> String {
        "\(sessionID.lowercased())\(JarvisConfig.sessionHostSuffix)"
    }

    /// Must equal GatewayConnectionController.manualStableID(host:port:) for a TLS host on 443.
    static func stableID(host: String) -> String {
        "manual|\(host.lowercased())|\(self.port)"
    }
}

/// What a refresh changes in the gateway registry. `managed` maps the stable ids this app created
/// from Jarvis to their session ids; only those are ever removed, so QR/manual gateways stay.
struct JarvisSyncPlan: Equatable, Sendable {
    struct Upsert: Equatable, Sendable {
        let sessionID: String
        let stableID: String
        let host: String
        let name: String
        let token: String?
        let connect: Bool
    }

    let upserts: [Upsert]
    let removals: [String]
    let managed: [String: String]

    static func make(remotes: [JarvisRemote], previouslyManaged: [String: String]) -> JarvisSyncPlan {
        var upserts: [Upsert] = []
        var managed: [String: String] = [:]
        for remote in remotes {
            let host = remote.gatewayHost ?? JarvisGatewayRoute.host(sessionID: remote.id)
            guard JarvisGatewayRoute.isSessionHost(host) else { continue }
            let stableID = JarvisGatewayRoute.stableID(host: host)
            managed[stableID] = remote.id
            upserts.append(Upsert(
                sessionID: remote.id,
                stableID: stableID,
                host: host,
                name: remote.displayTitle,
                token: remote.isConnectable ? remote.token : nil,
                connect: remote.isConnectable))
        }
        let removals = previouslyManaged.keys.filter { managed[$0] == nil }.sorted()
        return JarvisSyncPlan(upserts: upserts, removals: removals, managed: managed)
    }
}
