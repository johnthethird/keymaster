// Keymasterd-inetd — inetd-style Keychain access for launchd socket activation
//
// Build:  swiftc keymasterd-inetd.swift -o keymasterd-inetd
// Usage:  Designed to be spawned by launchd with socket activation
//
// This version reads HTTP request from stdin and writes response to stdout,
// suitable for launchd's inetdCompatibility mode.

import Foundation
import LocalAuthentication
import Security

// MARK: - Configuration

struct Config {
    var username: String = ""
    var password: String = ""
    var authDescription: String = "access the keychain key"

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

func authenticate(reason: String) -> (success: Bool, error: Error?) {
    let semaphore = DispatchSemaphore(value: 0)
    var authSuccess = false
    var authError: Error?

    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0

    var evalError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evalError) else {
        return (false, evalError)
    }

    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
        authSuccess = success
        authError = error
        semaphore.signal()
    }

    semaphore.wait()
    return (authSuccess, authError)
}

// MARK: - HTTP Processing

func httpResponse(status: Int, body: String, headers: [String: String] = [:]) -> String {
    let statusText: String
    switch status {
    case 200: statusText = "OK"
    case 400: statusText = "Bad Request"
    case 401: statusText = "Unauthorized"
    case 403: statusText = "Forbidden"
    case 404: statusText = "Not Found"
    case 405: statusText = "Method Not Allowed"
    default: statusText = "Unknown"
    }

    var response = "HTTP/1.1 \(status) \(statusText)\r\n"
    response += "Content-Type: text/plain\r\n"
    response += "Content-Length: \(body.utf8.count)\r\n"
    response += "Connection: close\r\n"

    for (key, value) in headers {
        response += "\(key): \(value)\r\n"
    }

    response += "\r\n"
    response += body

    return response
}

func processRequest(_ request: String) -> String {
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

        // Authenticate
        let reason = "\(config.authDescription): \"\(decodedKeyName)\""
        let (success, error) = authenticate(reason: reason)

        guard success else {
            let errorMsg = error?.localizedDescription ?? "Authentication failed"
            return httpResponse(status: 403, body: "Authentication failed: \(errorMsg)")
        }

        guard let password = getPassword(key: decodedKeyName) else {
            return httpResponse(status: 404, body: "Key not found")
        }

        return httpResponse(status: 200, body: password)
    }

    return httpResponse(status: 404, body: "Not Found")
}

// MARK: - Configuration

func loadConfig() {
    if let envUsername = ProcessInfo.processInfo.environment["KEYMASTERD_USERNAME"] {
        config.username = envUsername
    }
    if let envPassword = ProcessInfo.processInfo.environment["KEYMASTERD_PASSWORD"] {
        config.password = envPassword
    }
    if let envDescription = ProcessInfo.processInfo.environment["KEYMASTERD_DESCRIPTION"] {
        config.authDescription = envDescription
    }
}

// MARK: - Main

func main() {
    loadConfig()

    // Read HTTP request from stdin
    var requestData = Data()
    let bufferSize = 4096
    var buffer = [UInt8](repeating: 0, count: bufferSize)

    // Set stdin to non-blocking for timeout handling
    let flags = fcntl(STDIN_FILENO, F_GETFL)
    _ = fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK)

    // Read with timeout
    var attempts = 0
    let maxAttempts = 50  // 5 seconds total (50 * 100ms)

    while attempts < maxAttempts {
        let bytesRead = read(STDIN_FILENO, &buffer, bufferSize)
        if bytesRead > 0 {
            requestData.append(contentsOf: buffer[0..<bytesRead])
            // Check if we have a complete HTTP request (ends with \r\n\r\n)
            if let requestString = String(data: requestData, encoding: .utf8),
               requestString.contains("\r\n\r\n") {
                break
            }
        } else if bytesRead == 0 {
            // EOF
            break
        } else {
            // EAGAIN - no data available yet
            usleep(100_000)  // 100ms
            attempts += 1
        }
    }

    guard let request = String(data: requestData, encoding: .utf8), !request.isEmpty else {
        let response = httpResponse(status: 400, body: "No request received")
        print(response, terminator: "")
        return
    }

    let response = processRequest(request)
    print(response, terminator: "")
}

main()
