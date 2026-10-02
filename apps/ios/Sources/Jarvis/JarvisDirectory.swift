import AuthenticationServices
import Foundation
import Observation
import OpenClawKit
import UIKit

/// DE0CH fork: the paired Jarvis device token and the gateways this app created from Jarvis.
enum JarvisStore {
    private static let service = "dev.de0ch.openclaw.jarvis"
    private static let tokenAccount = "device-token"
    private static let managedDefaultsKey = "jarvis.managedGateways"

    static func loadToken() -> JarvisDeviceToken? {
        guard let json = GenericPasswordKeychainStore.loadString(service: self.service, account: self.tokenAccount),
              let data = json.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(JarvisDeviceToken.self, from: data)
    }

    @discardableResult
    static func saveToken(_ token: JarvisDeviceToken) -> Bool {
        guard let data = try? JSONEncoder().encode(token), let json = String(data: data, encoding: .utf8)
        else { return false }
        return GenericPasswordKeychainStore.saveString(json, service: self.service, account: self.tokenAccount)
    }

    static func clearToken() {
        GenericPasswordKeychainStore.delete(service: self.service, account: self.tokenAccount)
    }

    /// stable id -> Jarvis session id. Not secret: ids and hostnames only.
    static func loadManaged() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: self.managedDefaultsKey) as? [String: String] ?? [:]
    }

    static func saveManaged(_ managed: [String: String]) {
        UserDefaults.standard.set(managed, forKey: self.managedDefaultsKey)
    }

    /// Jarvis session hosts sit behind Cloudflare, whose certificates rotate: they use system
    /// trust only, never a first-use pin prompt.
    static func isManaged(stableID: String) -> Bool {
        self.loadManaged().keys.contains { GatewayStableIdentifier.matches($0, stableID) }
    }
}

struct JarvisClient: Sendable {
    enum Failure: Error, Equatable {
        case refused
        case http(Int)
        case network(String)
        case decode
    }

    private static let session: URLSession = {
        // Service-token headers only, never cookies: an Access cookie outlives a removed device.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.timeoutIntervalForRequest = 20
        return URLSession(configuration: configuration)
    }()

    func remotes(token: JarvisDeviceToken) async throws -> [JarvisRemote] {
        var components = URLComponents(
            url: JarvisConfig.baseURL.appendingPathComponent("api/remotes"),
            resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "harness", value: JarvisConfig.appName)]
        let data = try await self.send(URLRequest(url: components.url!), token: token)
        do {
            return try JSONDecoder().decode(JarvisRemotesResponse.self, from: data).sessions
        } catch {
            throw Failure.decode
        }
    }

    func start(sessionID: String, token: JarvisDeviceToken) async throws {
        let path = "api/sessions/\(sessionID)/start"
        var request = URLRequest(url: JarvisConfig.baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data("{}".utf8)
        _ = try await self.send(request, token: token)
    }

    private func send(_ request: URLRequest, token: JarvisDeviceToken) async throws -> Data {
        var request = request
        for (name, value) in token.accessHeaders {
            request.setValue(value, forHTTPHeaderField: name)
        }
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await Self.session.data(for: request)
        } catch {
            throw Failure.network(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else { throw Failure.network("no HTTP response") }
        if JarvisRefusal.isRefusal(
            finalURL: http.url,
            statusCode: http.statusCode,
            contentType: http.value(forHTTPHeaderField: "Content-Type"))
        {
            throw Failure.refused
        }
        guard (200..<300).contains(http.statusCode) else { throw Failure.http(http.statusCode) }
        return data
    }
}

@MainActor
@Observable
final class JarvisDirectory {
    static let shared = JarvisDirectory()

    private(set) var token: JarvisDeviceToken?
    private(set) var remotes: [JarvisRemote] = []
    private(set) var isBusy = false
    private(set) var statusText: String?
    private(set) var lastRefresh: Date?
    private(set) var startingSessionIDs: Set<String> = []
    private var authSession: ASWebAuthenticationSession?
    private let anchorProvider = JarvisAuthAnchorProvider()
    private let client = JarvisClient()

    var isPaired: Bool {
        self.token != nil
    }

    init() {
        self.token = JarvisStore.loadToken()
    }

    /// Pair this install with Jarvis in the system sign-in sheet (shares Safari's Access login).
    @discardableResult
    func signIn() async -> Bool {
        guard !self.isBusy else { return false }
        self.isBusy = true
        defer { self.isBusy = false }
        let state = JarvisPairing.makeState()
        guard let url = JarvisPairing.pairURL(
            state: state,
            deviceName: UIDevice.current.name,
            model: Self.modelIdentifier())
        else { return false }
        let result: Result<JarvisDeviceToken, JarvisPairingError> = await withCheckedContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callback: .customScheme(JarvisConfig.callbackScheme))
            { callbackURL, error in
                if let callbackURL {
                    continuation.resume(returning: JarvisPairing.parseCallback(callbackURL, expectedState: state))
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(returning: .failure(.cancelled))
                } else {
                    continuation.resume(returning: .failure(.failed(
                        error?.localizedDescription ?? "Sign-in did not finish.")))
                }
            }
            session.presentationContextProvider = self.anchorProvider
            session.prefersEphemeralWebBrowserSession = false
            self.authSession = session
            if !session.start() {
                continuation.resume(returning: .failure(.failed("Could not open the sign-in sheet.")))
            }
        }
        self.authSession = nil
        switch result {
        case let .success(token):
            guard JarvisStore.saveToken(token) else {
                self.statusText = "Could not save the Jarvis sign-in in the Keychain."
                return false
            }
            self.token = token
            self.statusText = nil
            return true
        case let .failure(error):
            self.statusText = error == .cancelled ? nil : error.message
            return false
        }
    }

    /// Fetch the OpenClaw sessions and mirror them into the gateway registry.
    func refresh(controller: GatewayConnectionController) async {
        guard let token, !self.isBusy else { return }
        self.isBusy = true
        defer { self.isBusy = false }
        do {
            let remotes = try await self.client.remotes(token: token)
            self.remotes = remotes
            self.lastRefresh = Date()
            self.statusText = nil
            await self.apply(remotes: remotes, token: token, controller: controller)
        } catch JarvisClient.Failure.refused {
            if JarvisRefusal.meansRevoked(token: token) {
                await self.forgetPairing(controller: controller)
                self.statusText = "This device was removed from Jarvis. Sign in again."
            } else {
                self.statusText = "Jarvis is still activating this device. Refresh in a few seconds."
            }
        } catch let JarvisClient.Failure.http(status) {
            self.statusText = "Jarvis answered HTTP \(status)."
        } catch let JarvisClient.Failure.network(detail) {
            self.statusText = "No response from Jarvis: \(detail)"
        } catch {
            self.statusText = "Jarvis sent an answer this app cannot read."
        }
    }

    /// Start a paused session, then refresh until it reports started (or 3 minutes pass).
    func start(_ remote: JarvisRemote, controller: GatewayConnectionController) async {
        guard let token, !self.startingSessionIDs.contains(remote.id) else { return }
        self.startingSessionIDs.insert(remote.id)
        defer { self.startingSessionIDs.remove(remote.id) }
        do {
            try await self.client.start(sessionID: remote.id, token: token)
        } catch {
            self.statusText = "Could not start \(remote.displayTitle)."
            return
        }
        for _ in 0..<36 {
            try? await Task.sleep(for: .seconds(5))
            await self.refresh(controller: controller)
            if self.remotes.first(where: { $0.id == remote.id })?.isConnectable == true { return }
        }
        self.statusText = "\(remote.displayTitle) has not come up yet. Refresh later."
    }

    /// Sign out: drop the device token and every gateway made from Jarvis.
    func forgetPairing(controller: GatewayConnectionController) async {
        for stableID in JarvisStore.loadManaged().keys {
            _ = await controller.forgetGateway(stableID: stableID)
        }
        JarvisStore.saveManaged([:])
        JarvisStore.clearToken()
        self.token = nil
        self.remotes = []
    }

    private func apply(
        remotes: [JarvisRemote],
        token: JarvisDeviceToken,
        controller: GatewayConnectionController) async
    {
        let plan = JarvisSyncPlan.make(remotes: remotes, previouslyManaged: JarvisStore.loadManaged())
        // Record ownership first so the connect path already treats these routes as Jarvis routes.
        JarvisStore.saveManaged(plan.managed.merging(JarvisStore.loadManaged()) { new, _ in new })
        let instanceID = GatewaySettingsStore.currentInstanceID()
        for upsert in plan.upserts {
            let entry = GatewaySettingsStore.GatewayRegistryEntry(
                stableID: upsert.stableID,
                kind: .manual,
                name: upsert.name,
                host: upsert.host,
                port: JarvisGatewayRoute.port,
                useTLS: true,
                contextPath: nil,
                lastConnectedAtMs: nil)
            guard GatewaySettingsStore.upsertGatewayRegistryEntry(entry) else { continue }
            _ = GatewaySettingsStore.saveGatewayCustomHeaders(token.accessHeaders, gatewayStableID: upsert.stableID)
            _ = GatewayTLSStore.clearFingerprint(stableID: upsert.stableID)
            if let gatewayToken = upsert.token {
                GatewaySettingsStore.saveGatewayCredentials(
                    token: gatewayToken,
                    bootstrapToken: nil,
                    password: nil,
                    gatewayStableID: upsert.stableID,
                    suppressStoredDeviceAuth: false,
                    instanceId: instanceID)
            }
            controller.setGatewayConnectionEnabled(stableID: upsert.stableID, enabled: upsert.connect)
        }
        for stableID in plan.removals {
            _ = await controller.forgetGateway(stableID: stableID)
        }
        JarvisStore.saveManaged(plan.managed)

        // Focus a started session when nothing usable is focused.
        let registry = GatewaySettingsStore.loadGatewayRegistry()
        let connectable = plan.upserts.filter(\.connect)
        let activeID = registry.activeStableID
        let activeIsUsable: Bool = {
            guard let activeID else { return false }
            guard JarvisStore.isManaged(stableID: activeID) else { return true }
            return connectable.contains { GatewayStableIdentifier.matches($0.stableID, activeID) }
        }()
        if !activeIsUsable, let first = connectable.first {
            _ = await controller.switchToGateway(stableID: first.stableID)
        }
    }

    private static func modelIdentifier() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let identifier = withUnsafeBytes(of: &systemInfo.machine) { buffer in
            String(bytes: buffer.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
        }
        return identifier.isEmpty ? UIDevice.current.model : identifier
    }
}

private final class JarvisAuthAnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow) ?? scenes.first?.windows.first
            return window ?? ASPresentationAnchor()
        }
    }
}
