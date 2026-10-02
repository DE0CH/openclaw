import SwiftUI

/// DE0CH fork: the Jarvis sign-in and the list of OpenClaw sessions Jarvis runs (Gateway settings).
struct JarvisSessionsSection: View {
    @Environment(GatewayConnectionController.self) private var gatewayController
    private var directory: JarvisDirectory {
        JarvisDirectory.shared
    }

    var body: some View {
        Section {
            if self.directory.isPaired {
                ForEach(self.directory.remotes) { remote in
                    self.row(remote)
                }
                if self.directory.remotes.isEmpty, self.directory.lastRefresh != nil {
                    Text("No OpenClaw sessions in Jarvis.")
                        .foregroundStyle(.secondary)
                }
                Button {
                    Task { await self.directory.refresh(controller: self.gatewayController) }
                } label: {
                    Label(self.directory.isBusy ? "Refreshing…" : "Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(self.directory.isBusy)
                Button(role: .destructive) {
                    Task { await self.directory.forgetPairing(controller: self.gatewayController) }
                } label: {
                    Label("Sign Out of Jarvis", systemImage: "rectangle.portrait.and.arrow.right")
                }
            } else {
                Button {
                    Task {
                        if await self.directory.signIn() {
                            await self.directory.refresh(controller: self.gatewayController)
                        }
                    }
                } label: {
                    Label("Sign In with Jarvis", systemImage: "person.badge.key")
                }
                .disabled(self.directory.isBusy)
            }
            if let status = self.directory.statusText {
                Text(verbatim: status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Jarvis")
        } footer: {
            Text("Every OpenClaw session in Jarvis appears here and as a gateway.")
        }
    }

    private func row(_ remote: JarvisRemote) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: remote.displayTitle)
                Text(verbatim: self.stateText(remote))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if remote.isConnectable, let host = remote.gatewayHost {
                Button("Open") {
                    Task {
                        _ = await self.gatewayController.switchToGateway(
                            stableID: JarvisGatewayRoute.stableID(host: host))
                    }
                }
                .buttonStyle(.bordered)
            } else if remote.state == .paused {
                let starting = self.directory.startingSessionIDs.contains(remote.id)
                Button(starting ? "Starting…" : "Start") {
                    Task { await self.directory.start(remote, controller: self.gatewayController) }
                }
                .buttonStyle(.bordered)
                .disabled(starting)
            }
        }
    }

    private func stateText(_ remote: JarvisRemote) -> String {
        switch remote.state {
        case .started: remote.isConnectable ? "Running" : "Starting…"
        case .paused: "Paused"
        case .other: "Unavailable"
        }
    }
}
