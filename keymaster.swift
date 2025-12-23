// Keymaster — secure Keychain helper guarded by Touch ID or your login password
//
// Build:  swiftc keymaster.swift -o keymaster
// Usage:  keymaster --help
// Forked: https://github.com/johnthethird/keymaster

import Foundation
import LocalAuthentication
import Security

// MARK: - Keychain helpers

@discardableResult
func setPassword(key: String, password: String) -> Bool {
    let passwordData = Data(password.utf8)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: key,
        kSecValueData as String: passwordData,
    ]

    // Try to add first; if it already exists, update.
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecDuplicateItem {
        let attrsToUpdate = [kSecValueData as String: passwordData]
        return SecItemUpdate(query as CFDictionary,
                             attrsToUpdate as CFDictionary) == errSecSuccess
    }
    return status == errSecSuccess
}

@discardableResult
func deletePassword(key: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: key,
    ]
    return SecItemDelete(query as CFDictionary) == errSecSuccess
}

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
          let pwd  = String(data: data, encoding: .utf8) else {
        return nil
    }
    return pwd
}

// MARK: - Authentication

/// Authenticate with Touch ID if available, otherwise the macOS login
/// password.  A single sheet is shown; pressing “Use Password…” switches
/// directly to the password prompt without needing a second call.
func authenticate(
    reason: String,
    context: LAContext = .init(),
    reply: @escaping (Bool, Error?) -> Void)
{
    // Force fresh biometrics every time.
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

// MARK: - CLI

func printHelp() {
    print(
    """
    Keymaster — store & retrieve small secrets in your macOS Keychain,
    protected by Touch ID or your login password.

    USAGE:
      keymaster set <key> <secret>              Store or update <secret> for <key>
      keymaster get <key> [options]             Print secret to stdout
      keymaster delete <key>                    Remove secret from Keychain

    OPTIONS:
      -h, --help                                Display this help message and exit
      -d, --description <text>                  Custom description for biometric prompt (get only)

    EXAMPLES:
      keymaster set github_token "abc123"
      keymaster get github_token
      keymaster get vpn_password --description "VPN wants to authenticate"
      keymaster delete github_token
    """)
}

func main() {
    var args = Array(CommandLine.arguments.dropFirst())

    // Early exit for --help.
    if let first = args.first, ["--help", "-h"].contains(first) {
        printHelp()
        exit(EXIT_SUCCESS)
    }

    guard args.count >= 2 else {
        printHelp()
        exit(EXIT_FAILURE)
    }

    let action = args.removeFirst()
    let key    = args.removeFirst()

    // Parse optional description for "get" command
    var customDescription: String?
    var secret = ""

    if action == "get" {
        // Check for --description or -d flag
        while !args.isEmpty {
            let arg = args.removeFirst()
            if arg == "--description" || arg == "-d" {
                if !args.isEmpty {
                    customDescription = args.removeFirst()
                }
            }
        }
    } else if action == "set" {
        secret = args.first ?? ""
    }

    // Build authentication reason
    let authReason: String
    if let description = customDescription {
        authReason = description
    } else {
        authReason = "\(action) the secret for \"\(key)\""
    }

    switch action {
    case "set", "get", "delete":
        // Show which key is being accessed
        if action == "get" {
            fputs("Reading key \"\(key)\" from Keychain...\n", stderr)
        }

        authenticate(reason: authReason) { success, error in
            guard success else {
                fputs("Authentication failed: \(error?.localizedDescription ?? "Unknown error")\n", stderr)
                exit(EXIT_FAILURE)
            }

            switch action {
            case "set":
                guard !secret.isEmpty else {
                    fputs("Error: <secret> missing for set action\n", stderr)
                    exit(EXIT_FAILURE)
                }
                guard setPassword(key: key, password: secret) else {
                    fputs("Error writing to Keychain\n", stderr)
                    exit(EXIT_FAILURE)
                }
                print("✔ Key \"\(key)\" stored successfully")

            case "get":
                guard let pwd = getPassword(key: key) else {
                    fputs("No item found for \"\(key)\"\n", stderr)
                    exit(EXIT_FAILURE)
                }
                print(pwd)

            case "delete":
                guard deletePassword(key: key) else {
                    fputs("Error deleting item for \"\(key)\"\n", stderr)
                    exit(EXIT_FAILURE)
                }
                print("✔ Key \"\(key)\" deleted successfully")
            default: break // Unreached
            }
            exit(EXIT_SUCCESS)
        }

        // Keep the process alive while the asynchronous auth prompt is shown.
        dispatchMain()

    default:
        printHelp()
        exit(EXIT_FAILURE)
    }
}

main()