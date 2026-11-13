// G-03 iOS (laboratory, not a product): the transaction key of D-25 on a REAL Secure Enclave. Creates a key (biometryCurrentSet),
// commits it, signs a v2 header (Face ID/Touch ID prompt), checks the signature with the public key, checks the header shape,
// and prints fixed lines `SENTOMARU-G03 <id> PASS|FAIL|MEASURED`. No server, no network, no identifier. The key is deleted at the end.
// Run: xcrun devicectl device process launch --console --device <udid> com.example.app   (the person must be at the device)
import CryptoKit
import Foundation
import LocalAuthentication
import Sentomaru
import SentomaruCore
import UIKit

func emit(_ id: String, _ verdict: String, _ note: String = "") {
    print("SENTOMARU-G03 \(id) \(verdict) \(note)".trimmingCharacters(in: .whitespaces))
    fflush(stdout)
}

/// One signature attempt with its duration: a prompt that a person answers takes seconds, an answer in a few hundred ms means
/// the system showed no prompt (authentication reused). `PROMPT` lines tell the person what to do BEFORE the call.
func attempt(_ signer: TransactionSigner, _ id: String, _ instruction: String, _ op: String, _ body: Data) async -> (header: String?, ms: Int) {
    print("SENTOMARU-G03 PROMPT \(id) \(instruction)"); fflush(stdout)
    let start = DispatchTime.now().uptimeNanoseconds
    var header: String?
    var outcome = "signed"
    do { header = try await signer.sign(operationId: op, body: body, reason: "Prova G-03 \(id): \(instruction)") }
    catch TransactionError.cancelled { outcome = "cancelled" }
    catch { outcome = "error:\(error)" }
    let ms = Int((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
    emit(id, "MEASURED", "outcome=\(outcome) ms=\(ms) prompt-shown=\(ms >= 600 ? "likely" : "inconclusive")")
    return (header, ms)
}

/// Diagnostics (I2): what the system says about biometrics BEFORE an attempt. A fresh context each time, never reused.
func probe(_ id: String) async {
    let state = await MainActor.run { UIApplication.shared.applicationState.rawValue }
    let ctx = LAContext()
    var err: NSError?
    let ok = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    emit(id + "-probe", "MEASURED", "canEvaluate=\(ok) biometryType=\(ctx.biometryType.rawValue) laerr=\(err?.code ?? 0) reuseDuration=\(ctx.touchIDAuthenticationAllowableReuseDuration) app-state=\(state)")
}

/// Same access control as the SDK key, a fresh LAContext, and the RAW error (the SDK maps every error to a closed set and
/// hides the LAError code). The key lives only in this process. `userPresence` allows the passcode, `biometryCurrentSet` does not.
func rawAttempt(_ id: String, _ instruction: String, biometricOnly: Bool) async {
    do {
        let flags: SecAccessControlCreateFlags = biometricOnly ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage, .userPresence]
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, nil) else { emit(id, "FAIL", "no-access-control"); return }
        let blob = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access).dataRepresentation
        await probe(id)
        print("SENTOMARU-G03 PROMPT \(id) \(instruction)"); fflush(stdout)
        let start = DispatchTime.now().uptimeNanoseconds
        let outcome: String = await Task.detached {
            let ctx = LAContext()
            ctx.localizedReason = "Prova G-03 \(id)"
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                _ = try key.signature(for: Data("g03 raw".utf8))
                return "signed"
            } catch let e as LAError { return "LAError.\(e.code.rawValue) \(e.code)" }
            catch { let ns = error as NSError; return "error domain=\(ns.domain) code=\(ns.code)" }
        }.value
        let ms = Int((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
        emit(id, "MEASURED", "flags=\(biometricOnly ? "biometryCurrentSet" : "userPresence") outcome=\(outcome) ms=\(ms)")
    } catch { emit(id, "FAIL", "setup:\(error)") }
}

/// I-3n: the cache question WITHOUT a face. A fresh LAContext with `interactionNotAllowed` may not show any prompt, so a signature
/// can only come from an authentication the system kept (a reuse window). `signed` = a hidden cache exists (FAIL); a not-interactive
/// error = nothing was kept (PASS). It does not depend on the person's face, which is what made I-3a ambiguous: Face ID signs by
/// itself when it recognises a partly covered face. The raw error is logged. Limit: it proves the absence of reuse for a fresh
/// context with reuseDuration 0, not that cancelling a real prompt works (that stays with I-3a).
func noPromptAttempt(_ id: String, _ when: String) async -> String {
    do {
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil) else { emit(id, "FAIL", "no-access-control"); return "setup" }
        let blob = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access).dataRepresentation
        let start = DispatchTime.now().uptimeNanoseconds
        let outcome: String = await Task.detached {
            let ctx = LAContext()
            ctx.interactionNotAllowed = true
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                _ = try key.signature(for: Data("g03 no prompt".utf8))
                return "signed"
            } catch let e as LAError { return "LAError.\(e.code.rawValue) \(e.code)" }
            catch { let ns = error as NSError; return "error domain=\(ns.domain) code=\(ns.code)" }
        }.value
        let ms = Int((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
        let kind = outcome == "signed" ? "signed" : (outcome.contains("-1004") || outcome.contains("notInteractive") || outcome.contains("-25308") ? "refused" : "other")
        emit(id, kind == "signed" ? "FAIL" : (kind == "refused" ? "PASS" : "MEASURED"), "when=\(when) outcome=\(outcome) ms=\(ms) \(kind == "signed" ? "hidden-auth-cache" : (kind == "refused" ? "no-auth-kept" : "inconclusive-error"))")
        return kind
    } catch { emit(id, "FAIL", "setup:\(error)"); return "setup" }
}

func runG03() async {
    let keys = SecureEnclaveTransactionKeys(service: "br.com.ebees.sentomaru.g03lab")
    let signer = TransactionSigner(keys: keys, installationAlias: "g03.lab")
    defer { signer.discard() }
    guard SecureEnclave.isAvailable else { emit("I-0", "FAIL", "no-secure-enclave"); return }
    signer.discard()
    do {
        let spki = try signer.stageKey(biometricOnly: true)
        try signer.commitKey()
        emit("I-1", signer.isEnrolled() && spki.count == 91 ? "PASS" : "FAIL", "spki=\(spki.count)")
        let publicKey = try P256.Signing.PublicKey(derRepresentation: spki)
        let op = "g03-lab-operation-0001", body = Data("g03 body".utf8)

        // I-0w warm-up: consumes the one-time system permission alert for Face ID (TCC, NSFaceIDUsageDescription) so that it cannot
        // be mistaken for the I-3a prompt. The person allows it and authenticates normally. Not part of any verdict.
        await rawAttempt("I-0w", "AQUECIMENTO: se aparecer alerta pedindo permissao do Face ID, toque em Permitir; depois AUTENTIQUE normalmente", biometricOnly: true)

        // I-3n-0: before any authentication in this run, no prompt allowed: nothing may sign.
        var cache = [await noPromptAttempt("I-3n-0", "before-any-auth")]

        // I-3a: cancel FIRST, before any authentication in this run. A `signed` here is ambiguous: Face ID signs by itself when it
        // recognises a partly covered face (rounds 2 and 3 signed in ~1.7-2 s). So up to 3 tries, each asking to hide the WHOLE face;
        // the verdict is PASS on the first cancel, and `signed` on all tries is INCONCLUSIVE (face recognised), not a defect, unless
        // the I-3n lines say a hidden authentication cache exists.
        var cancelledAt = 0
        for n in 1...3 {
            await probe("I-3a")
            let a = await attempt(signer, "I-3a", n == 1 ? "CANCELE: cubra o rosto ou olhe para o lado e ENTAO toque em Cancelar"
                : "TENTATIVA \(n) de 3: o Face ID reconheceu voce. Tampe o rosto INTEIRO com a mao (olhos, nariz e boca) ou vire a tela para baixo, espere o Face ID falhar e ENTAO toque em Cancelar", op, body)
            emit("I-3a-try-\(n)", a.header == nil ? "PASS" : "MEASURED", a.header == nil ? "cancelled" : "signed-face-recognised-or-reused ms=\(a.ms)")
            if a.header == nil { cancelledAt = n; break }
        }
        emit("I-3a-verdict", cancelledAt > 0 ? "PASS" : "MEASURED", cancelledAt > 0 ? "cancelled-before-any-auth try=\(cancelledAt)" : "signed-on-3-tries INCONCLUSIVE face-recognised-or-reuse (I-3n decides)")
        emit("I-3a-key", signer.isEnrolled() ? "PASS" : "FAIL", "key-kept-after-cancel")

        // I-2: authenticate; the signature must verify.
        let before = Int(Date().timeIntervalSince1970)
        let b = await attempt(signer, "I-2", "AUTENTIQUE (rosto/digital)", op, body)
        if let header = b.header {
            let parts = header.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            emit("I-2a", TransactionSignature.isHeaderValue(header) && parts.count == 4 && parts[0] == TransactionSignature.version2 ? "PASS" : "FAIL", "v2-shape")
            if parts.count == 4, let issued = Int(parts[2]), let nonce = Data(base64URL: parts[1]), let sig = Data(base64URL: parts[3]) {
                emit("I-2b", abs(issued - before) <= 60 ? "PASS" : "FAIL", "issuedAt-delta=\(issued - before)")
                let message = TransactionSignature.message(nonce: nonce, issuedAt: issued, operationId: op, body: body)
                let ok = (try? P256.Signing.ECDSASignature(rawRepresentation: sig)).map { publicKey.isValidSignature($0, for: message) } ?? false
                emit("I-2c", ok ? "PASS" : "FAIL", "signature-verifies")
            }
        } else { emit("I-2a", "FAIL", "not-signed") }

        // I-3n-1: right after the successful authentication, no prompt allowed: a reuse window would sign here.
        cache.append(await noPromptAttempt("I-3n-1", "right-after-auth"))

        // I-3b: right after a successful authentication, ask again and CANCEL.
        let c = await attempt(signer, "I-3b", "CANCELE: cubra o rosto ou olhe para o lado e ENTAO toque em Cancelar (logo depois de autenticar)", op, body)
        emit("I-3b-verdict", c.header == nil ? "PASS" : "MEASURED", c.header == nil ? "cancelled" : "signed-again-ms=\(c.ms)")

        // I-3c: 15 s later, ask again and CANCEL.
        print("SENTOMARU-G03 WAIT 15s"); fflush(stdout)
        try? await Task.sleep(nanoseconds: 15_000_000_000)
        cache.append(await noPromptAttempt("I-3n-2", "15s-after-auth"))
        let d = await attempt(signer, "I-3c", "CANCELE: cubra o rosto ou olhe para o lado e ENTAO toque em Cancelar (15 s depois)", op, body)
        emit("I-3c-verdict", d.header == nil ? "PASS" : "MEASURED", d.header == nil ? "cancelled" : "signed-again-ms=\(d.ms)")

        emit("I-3n-verdict", cache.contains("signed") ? "FAIL" : (cache.allSatisfy { $0 == "refused" } ? "PASS" : "MEASURED"), "results=\(cache.joined(separator: ","))")

        // I-4 (raw, CryptoKit direct, fresh LAContext, LAError code logged). Face ID authenticates BY ITSELF when it sees the
        // face, so a "cancel" is a race the person can lose: cover/turn the face away first, THEN tap Cancel.
        await rawAttempt("I-4a", "CUBRA o rosto (Face ID nao pode reconhecer) e toque em Cancelar", biometricOnly: true)
        await rawAttempt("I-4b", "CUBRA o rosto, falhe o Face ID e, se aparecer, use a SENHA do aparelho (userPresence)", biometricOnly: false)
        // I-4c: the question left open by I-4a/I-4b. Same key as the SDK (biometryCurrentSet, no passcode in the access control), face covered
        // so Face ID FAILS, and the person types the device passcode IF the system offers it. signed = the passcode signs with a
        // biometryCurrentSet key; cancelled/LAError without a signature = it does not. The log cannot say which factor signed: the person
        // writes it down ("senha" or "rosto"). Run once; no repeat until it passes.
        await rawAttempt("I-4c", "CUBRA o rosto (Face ID tem que FALHAR). Se o sistema oferecer a SENHA, DIGITE a senha do aparelho e ANOTE 'senha'; se nao oferecer, toque em Cancelar e ANOTE 'sem senha'. Se assinar por rosto, ANOTE 'rosto'", biometricOnly: true)
    } catch { emit("I-ERR", "FAIL", "\(error)") }
}

extension Data {
    init?(base64URL s: String) {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        self.init(base64Encoded: t)
    }
}

@MainActor
final class G03Controller: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let label = UILabel(frame: view.bounds.insetBy(dx: 16, dy: 60))
        label.numberOfLines = 0
        label.text = "G-03 iOS: siga o terminal do Mac"
        view.addSubview(label)
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        Task { await runG03(); emit("DONE", "MEASURED") }
    }
}

@main
final class G03Delegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool { true }
}

@objc(LabSceneDelegate)
final class LabSceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = G03Controller()
        window.makeKeyAndVisible()
        self.window = window
    }
}
