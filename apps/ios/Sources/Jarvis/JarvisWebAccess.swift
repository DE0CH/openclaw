import Foundation
import WebKit

/// DE0CH fork: Control UI pages of a Jarvis session load through Cloudflare Access. WKWebView can't
/// add headers to subresource or WebSocket loads, so the page first gets the Access cookie that a
/// service-token request earns (CF_Authorization, valid 24 h), and the main document also carries
/// the headers. The cookie lives only in this view's non-persistent data store.
@MainActor
enum JarvisWebAccess {
    static func headers(for url: URL) -> [String: String]? {
        guard let host = url.host, JarvisGatewayRoute.isSessionHost(host),
              let token = JarvisStore.loadToken()
        else { return nil }
        return token.accessHeaders
    }

    static func load(_ webView: WKWebView, url: URL, headers: [String: String]) {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        Task { @MainActor [weak webView] in
            let cookies = await self.accessCookies(for: url, headers: headers)
            guard let webView else { return }
            let store = webView.configuration.websiteDataStore.httpCookieStore
            for cookie in cookies {
                await store.setCookie(cookie)
            }
            webView.load(request)
        }
    }

    static func accessCookies(for url: URL, headers: [String: String]) async -> [HTTPCookie] {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return [] }
        components.path = "/"
        components.query = nil
        components.fragment = nil
        guard let origin = components.url else { return [] }
        var request = URLRequest(url: origin, cachePolicy: .reloadIgnoringLocalCacheData)
        request.httpMethod = "HEAD"
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 15
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        guard let (_, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse
        else { return [] }
        return self.cookies(from: http, for: origin)
    }

    static func cookies(from response: HTTPURLResponse, for url: URL) -> [HTTPCookie] {
        var fields: [String: String] = [:]
        for (key, value) in response.allHeaderFields {
            if let key = key as? String, let value = value as? String {
                fields[key] = value
            }
        }
        return HTTPCookie.cookies(withResponseHeaderFields: fields, for: url)
            .filter { $0.name == "CF_Authorization" }
    }
}
