// Keymasterd — HTTP daemon for secure Keychain access guarded by Touch ID or login password
//
// Build:  swiftc keymasterd.swift -o keymasterd
// Usage:  keymasterd --help

import Foundation
import LocalAuthentication
import Security

// MARK: - Configuration

struct Config {
    var port: UInt16 = 8787
    var host: String = "127.0.0.1"
    var username: String = ""
    var password: String = ""
    var authDescription: String = "Keymasterd wants to access the Keychain"

    var requireAuth: Bool {
        return !username.isEmpty && !password.isEmpty
    }
}

var config = Config()

// MARK: - Keychain helpers

func getPassword(key: String) -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: key,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecReturnData as String: true,
    ]

    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data,
          let pwd = String(data: data, encoding: .utf8) else {
        return nil
    }
    return pwd
}

// MARK: - Authentication

func authenticate(
    reason: String,
    context: LAContext = .init(),
    reply: @escaping (Bool, Error?) -> Void)
{
    context.touchIDAuthenticationAllowableReuseDuration = 0

    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        reply(false, error)
        return
    }

    context.evaluatePolicy(.deviceOwnerAuthentication,
                           localizedReason: reason,
                           reply: reply)
}

// MARK: - HTTP Server

class HTTPServer {
    private var serverSocket: Int32 = -1
    private let queue = DispatchQueue(label: "keymasterd.http", attributes: .concurrent)

    func start(host: String, port: UInt16) throws {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            throw NSError(domain: "HTTPServer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create socket"])
        }

        var opt: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian

        if host == "0.0.0.0" {
            addr.sin_addr.s_addr = INADDR_ANY
        } else {
            addr.sin_addr.s_addr = inet_addr(host)
        }

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard bindResult >= 0 else {
            close(serverSocket)
            throw NSError(domain: "HTTPServer", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to bind to \(host):\(port)"])
        }

        guard listen(serverSocket, 10) >= 0 else {
            close(serverSocket)
            throw NSError(domain: "HTTPServer", code: 3, userInfo: [NSLocalizedDescriptionKey: "Failed to listen"])
        }

        log("Keymasterd listening on http://\(host):\(port)")
        if config.requireAuth {
            log("HTTP Basic Authentication: enabled")
        } else {
            log("HTTP Basic Authentication: disabled (no credentials configured)")
        }

        acceptConnections()
    }

    private func acceptConnections() {
        queue.async { [weak self] in
            guard let self = self else { return }

            while true {
                var clientAddr = sockaddr_in()
                var clientAddrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

                let clientSocket = withUnsafeMutablePointer(to: &clientAddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        accept(self.serverSocket, $0, &clientAddrLen)
                    }
                }

                if clientSocket < 0 {
                    continue
                }

                self.queue.async {
                    self.handleClient(socket: clientSocket)
                }
            }
        }
    }

    private func handleClient(socket clientSocket: Int32) {
        defer { close(clientSocket) }

        var buffer = [UInt8](repeating: 0, count: 4096)
        let bytesRead = read(clientSocket, &buffer, buffer.count)

        guard bytesRead > 0 else { return }

        let request = String(bytes: buffer[0..<bytesRead], encoding: .utf8) ?? ""
        let response = processRequest(request)

        _ = response.withCString { ptr in
            write(clientSocket, ptr, strlen(ptr))
        }
    }

    private func processRequest(_ request: String) -> String {
        let lines = request.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            return httpResponse(status: 400, body: "Bad Request")
        }

        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else {
            return httpResponse(status: 400, body: "Bad Request")
        }

        let method = parts[0]
        let path = parts[1]

        // Check HTTP Basic Auth if configured
        if config.requireAuth {
            var authorized = false
            for line in lines {
                if line.lowercased().hasPrefix("authorization:") {
                    let authValue = line.dropFirst("authorization:".count).trimmingCharacters(in: .whitespaces)
                    if authValue.lowercased().hasPrefix("basic ") {
                        let base64Credentials = String(authValue.dropFirst("basic ".count))
                        if let credentialsData = Data(base64Encoded: base64Credentials),
                           let credentials = String(data: credentialsData, encoding: .utf8) {
                            let expectedCredentials = "\(config.username):\(config.password)"
                            authorized = (credentials == expectedCredentials)
                        }
                    }
                }
            }

            if !authorized {
                return httpResponse(status: 401, body: "Unauthorized", headers: ["WWW-Authenticate": "Basic realm=\"Keymasterd\""])
            }
        }

        // Route handling
        guard method == "GET" else {
            return httpResponse(status: 405, body: "Method Not Allowed")
        }

        // Health check endpoint
        if path == "/health" {
            return httpResponse(status: 200, body: "OK")
        }

        // Key retrieval: /key/<keyname>
        if path.hasPrefix("/key/") {
            let keyName = String(path.dropFirst("/key/".count))
            guard !keyName.isEmpty else {
                return httpResponse(status: 400, body: "Key name required")
            }

            // URL decode the key name
            let decodedKeyName = keyName.removingPercentEncoding ?? keyName

            return handleGetKey(keyName: decodedKeyName)
        }

        return httpResponse(status: 404, body: "Not Found")
    }

    private func handleGetKey(keyName: String) -> String {
        log("Request for key: \(keyName)")

        let semaphore = DispatchSemaphore(value: 0)
        var authSuccess = false
        var authError: Error?

        // Run authentication on main thread for UI prompt
        DispatchQueue.main.async {
            let reason = "\(config.authDescription): \"\(keyName)\""
            authenticate(reason: reason) { success, error in
                authSuccess = success
                authError = error
                semaphore.signal()
            }
        }

        semaphore.wait()

        guard authSuccess else {
            let errorMsg = authError?.localizedDescription ?? "Authentication failed"
            log("Authentication failed for key \(keyName): \(errorMsg)")
            return httpResponse(status: 403, body: "Authentication failed: \(errorMsg)")
        }

        guard let password = getPassword(key: keyName) else {
            log("Key not found: \(keyName)")
            return httpResponse(status: 404, body: "Key not found")
        }

        log("Successfully retrieved key: \(keyName)")
        return httpResponse(status: 200, body: password, contentType: "text/plain")
    }

    private func httpResponse(status: Int, body: String, contentType: String = "text/plain", headers: [String: String] = [:]) -> String {
        let statusText: String
        switch status {
        case 200: statusText = "OK"
        case 400: statusText = "Bad Request"
        case 401: statusText = "Unauthorized"
        case 403: statusText = "Forbidden"
        case 404: statusText = "Not Found"
        case 405: statusText = "Method Not Allowed"
        case 500: statusText = "Internal Server Error"
        default: statusText = "Unknown"
        }

        var response = "HTTP/1.1 \(status) \(statusText)\r\n"
        response += "Content-Type: \(contentType)\r\n"
        response += "Content-Length: \(body.utf8.count)\r\n"
        response += "Connection: close\r\n"

        for (key, value) in headers {
            response += "\(key): \(value)\r\n"
        }

        response += "\r\n"
        response += body

        return response
    }

    func stop() {
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
    }
}

// MARK: - Logging

func log(_ message: String) {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    let timestamp = formatter.string(from: Date())
    fputs("[\(timestamp)] \(message)\n", stderr)
}

// MARK: - CLI

func printHelp() {
    print(
    """
    Keymasterd — HTTP daemon for secure Keychain access,
    protected by Touch ID or your login password.

    USAGE:
      keymasterd [options]

    OPTIONS:
      -p, --port <port>           Port to listen on (default: 8787)
      -b, --bind <host>           Host/IP to bind to (default: 127.0.0.1)
      -u, --username <user>       HTTP Basic Auth username
      -d, --description <text>    Custom description for biometric prompt
      -h, --help                  Display this help message and exit

    ENVIRONMENT VARIABLES:
      KEYMASTERD_PASSWORD         HTTP Basic Auth password (required with -u)
      KEYMASTERD_USERNAME         HTTP Basic Auth username (alternative to -u)
      KEYMASTERD_PORT             Port to listen on (alternative to -p)
      KEYMASTERD_BIND             Host/IP to bind to (alternative to -b)

    ENDPOINTS:
      GET /key/<keyname>          Retrieve a secret from the Keychain
      GET /health                 Health check endpoint

    EXAMPLES:
      # Start with defaults (localhost:8787, no auth)
      keymasterd

      # Start on custom port with HTTP Basic Auth (password via env)
      KEYMASTERD_PASSWORD=secret123 keymasterd --port 9000 --username admin

      # All config via environment variables
      KEYMASTERD_USERNAME=admin KEYMASTERD_PASSWORD=secret123 keymasterd

      # Bind to all interfaces (use with caution!)
      KEYMASTERD_PASSWORD=mypass keymasterd --bind 0.0.0.0 --port 8787 -u myuser

    CURL USAGE:
      # Without auth
      curl http://localhost:8787/key/my_secret_key

      # With HTTP Basic Auth
      curl -u admin:secret123 http://localhost:8787/key/my_secret_key

      # Health check
      curl http://localhost:8787/health

    LAUNCHD:
      To run as a macOS service, create a plist in ~/Library/LaunchAgents/
      See README.md for a complete example.

    SECURITY NOTES:
      - Password is read from KEYMASTERD_PASSWORD env var (not visible in ps)
      - Default binding to 127.0.0.1 restricts access to localhost only
      - Always use HTTP Basic Auth when exposing to network
      - Each key request triggers a biometric/password prompt
      - Consider using HTTPS via a reverse proxy for production
    """)
}

func parseArguments() {
    // First, read environment variables as defaults
    if let envPort = ProcessInfo.processInfo.environment["KEYMASTERD_PORT"],
       let port = UInt16(envPort) {
        config.port = port
    }
    if let envHost = ProcessInfo.processInfo.environment["KEYMASTERD_BIND"] {
        config.host = envHost
    }
    if let envUsername = ProcessInfo.processInfo.environment["KEYMASTERD_USERNAME"] {
        config.username = envUsername
    }
    if let envPassword = ProcessInfo.processInfo.environment["KEYMASTERD_PASSWORD"] {
        config.password = envPassword
    }

    // Command-line arguments override environment variables
    var args = Array(CommandLine.arguments.dropFirst())

    while !args.isEmpty {
        let arg = args.removeFirst()

        switch arg {
        case "-h", "--help":
            printHelp()
            exit(EXIT_SUCCESS)

        case "-p", "--port":
            guard !args.isEmpty, let port = UInt16(args.removeFirst()) else {
                fputs("Error: --port requires a valid port number\n", stderr)
                exit(EXIT_FAILURE)
            }
            config.port = port

        case "-b", "--bind":
            guard !args.isEmpty else {
                fputs("Error: --bind requires a host/IP address\n", stderr)
                exit(EXIT_FAILURE)
            }
            config.host = args.removeFirst()

        case "-u", "--username":
            guard !args.isEmpty else {
                fputs("Error: --username requires a value\n", stderr)
                exit(EXIT_FAILURE)
            }
            config.username = args.removeFirst()

        case "-d", "--description":
            guard !args.isEmpty else {
                fputs("Error: --description requires a value\n", stderr)
                exit(EXIT_FAILURE)
            }
            config.authDescription = args.removeFirst()

        default:
            fputs("Unknown option: \(arg)\n", stderr)
            printHelp()
            exit(EXIT_FAILURE)
        }
    }

    // Warn if only one of username/password is set
    if (config.username.isEmpty && !config.password.isEmpty) ||
       (!config.username.isEmpty && config.password.isEmpty) {
        fputs("Warning: Both username and KEYMASTERD_PASSWORD must be set for HTTP Basic Auth\n", stderr)
    }
}

func main() {
    parseArguments()

    let server = HTTPServer()

    // Handle SIGINT/SIGTERM for graceful shutdown
    signal(SIGINT) { _ in
        log("Received SIGINT, shutting down...")
        exit(EXIT_SUCCESS)
    }
    signal(SIGTERM) { _ in
        log("Received SIGTERM, shutting down...")
        exit(EXIT_SUCCESS)
    }

    do {
        try server.start(host: config.host, port: config.port)
    } catch {
        fputs("Error starting server: \(error.localizedDescription)\n", stderr)
        exit(EXIT_FAILURE)
    }

    // Keep the main run loop alive
    dispatchMain()
}

main()
