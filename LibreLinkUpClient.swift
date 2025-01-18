//
//  LibreLinkUpClient.swift
//  Glucow
//
//  Created by Mathieu Fitzgerald on 12.01.2025.
//


import Foundation
import CommonCrypto
import CryptoKit

class LibreLinkUpClient {
    static let shared = LibreLinkUpClient()

    private var baseURL = URL(string: "https://api.libreview.io")!
    
    // re-use session to limit requests and bypass rate-limiting
    private lazy var urlSession: URLSession = {
        URLSession(configuration: .default)
    }()

    func login(email: String, password: String, completion: @escaping (Result<Void, Error>) -> Void) {
        postLogin(email: email, password: password) { result in
            switch result {
            case .failure(let err):
                completion(.failure(err))
            case .success(let responseDict):
                self.handleLoginResponse(email: email,
                                         password: password,
                                         responseDict: responseDict,
                                         completion: completion)
            }
        }
    }

    private func postLogin(email: String,
                           password: String,
                           completion: @escaping (Result<[String:Any], Error>) -> Void) {
        let url = baseURL.appendingPathComponent("/llu/auth/login")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("gzip",              forHTTPHeaderField: "accept-encoding")
        req.setValue("no-cache",          forHTTPHeaderField: "cache-control")
        req.setValue("Keep-Alive",        forHTTPHeaderField: "connection")
        
        req.setValue("llu.android", forHTTPHeaderField: "product")
        req.setValue("4.12",        forHTTPHeaderField: "version")
        req.setValue("Mozilla/5.0 (Windows NT 10.0; rv:129.0) Gecko/20100101 Firefox/129.0",  forHTTPHeaderField: "user-agent")

        let bodyObj = [ "email": email, "password": password ]
        do {
            req.httpBody = try JSONSerialization.data(withJSONObject: bodyObj, options: [])
        } catch {
            return completion(.failure(error))
        }

        let task = urlSession.dataTask(with: req) { data, resp, err in
            if let err = err { return completion(.failure(err)) }
            guard let data = data else {
                return completion(.failure(NSError(domain: "No data", code: 0)))
            }
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String:Any] {
                    completion(.success(json))
                } else {
                    completion(.failure(NSError(domain: "Bad JSON format", code: 0)))
                }
            } catch {
                completion(.failure(error))
            }
        }
        task.resume()
    }
    
    private func sha256Hex(_ input: String) -> String {
        guard let inputData = input.data(using: .utf8) else { return "" }
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        inputData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(inputData.count), &hash)
        }
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }


    private func handleLoginResponse(email: String,
                                     password: String,
                                     responseDict: [String:Any],
                                     completion: @escaping (Result<Void, Error>) -> Void) {
        // Check for redirect => region
        if let dataDict = responseDict["data"] as? [String:Any],
           let redirectVal = dataDict["redirect"] as? Bool, 
           redirectVal == true {
            // Suppose dataDict["region"] = "us" or something
            if let region = dataDict["region"] as? String {
                // If needed:
                // self.baseURL = URL(string: "https://api-\(region).libreview.io")!
                // Then re-login
                postLogin(email: email, password: password, completion: { result in
                    switch result {
                    case .failure(let err):
                        completion(.failure(err))
                    case .success(let newResponse):
                        self.handleLoginResponse(email: email,
                                                 password: password,
                                                 responseDict: newResponse,
                                                 completion: completion)
                    }
                })
                return
            }
        }

        // Check status
        if let status = responseDict["status"] as? Int {
            if status == 4 {
                // Terms & Conditions acceptance path
                self.doAuthContinue(prevResponse: responseDict, email: email, password: password, completion: completion)
                return
            }
            else if status == 0 {
                // success
                guard let dataDict = responseDict["data"] as? [String:Any],
                      let authTicket = dataDict["authTicket"] as? [String:Any],
                      let token = authTicket["token"] as? String,
                      let userDict = dataDict["user"] as? [String:Any],
                      let userId = userDict["id"] as? String
                else {
                    return completion(.failure(NSError(domain: "Missing token/userId", code: 0)))
                }

                // Save in UserDefaults
                let accountIdHash = sha256Hex(userId)
                UserDefaults.standard.set(token, forKey: "authToken")
                UserDefaults.standard.set(userId, forKey: "userId")
                UserDefaults.standard.set(accountIdHash, forKey: "accountIdHash")

                completion(.success(()))
                return
            }
            else {
                // Some other errors if needed
                return completion(.failure(NSError(domain: "Login status=\(status)", code: 0)))
            }
        }

        return completion(.failure(NSError(domain: "Unexpected response", code: 0)))
    }

    private func doAuthContinue(prevResponse: [String:Any],
                                email: String,
                                password: String,
                                completion: @escaping (Result<Void, Error>) -> Void) {
        guard let dataDict = prevResponse["data"] as? [String:Any],
              let stepDict = dataDict["step"] as? [String:Any],
              let stepType = stepDict["type"] as? String,
              let authTicket = dataDict["authTicket"] as? [String:Any],
              let token = authTicket["token"] as? String
        else {
            return completion(.failure(NSError(domain: "Missing step type or token", code: 0)))
        }

        // POST /auth/continue/
        var continueUrl = baseURL.appendingPathComponent("/auth/continue/\(stepType)")
        var req = URLRequest(url: continueUrl)
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let task = urlSession.dataTask(with: req) { data, resp, err in
            if let err = err { return completion(.failure(err)) }
            guard let data = data else {
                return completion(.failure(NSError(domain: "No data from T&C acceptance", code: 0)))
            }
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String:Any] {
                    // Now we should hopefully get status=0 if all ok
                    self.handleLoginResponse(email: email,
                                             password: password,
                                             responseDict: json,
                                             completion: completion)
                } else {
                    completion(.failure(NSError(domain: "Bad T&C JSON", code: 0)))
                }
            } catch {
                completion(.failure(error))
            }
        }
        task.resume()
    }
}
