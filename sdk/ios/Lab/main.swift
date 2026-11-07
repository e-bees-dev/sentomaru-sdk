// D-27 iOS proof app (laboratory, not a product): shows and prints the screen_shared observation of the Sentomaru SDK
// (UIScreen.screens / isCaptured) at launch and whenever the capture state or the screen set changes. Prints fixed codes only:
// no identifier, no personal data. Run with `xcrun devicectl device process launch --console ...` to read the lines.
import Sentomaru
import UIKit

@MainActor
final class LabController: UIViewController {
    private let label = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        label.numberOfLines = 0
        label.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        label.frame = view.bounds.insetBy(dx: 16, dy: 60)
        label.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(label)
        let center = NotificationCenter.default
        for name in [UIScreen.capturedDidChangeNotification, UIScreen.didConnectNotification, UIScreen.didDisconnectNotification] {
            center.addObserver(self, selector: #selector(refresh(_:)), name: name, object: nil)
        }
        report("launch")
    }

    @objc private func refresh(_ note: Notification) { report(note.name.rawValue) }

    private func report(_ reason: String) {
        let snapshot = SignalsCollector().snapshot(screen: true)
        var lines = ["event=\(reason)", "catalog=\(snapshot.catalogVersion)"]
        for o in snapshot.observations where o.capabilityId.hasPrefix("screen_") {
            let detail = o.detail.keys.sorted().map { "\($0)=\(o.detail[$0]!)" }.joined(separator: ",")
            lines.append("\(o.capabilityId) state=\(o.state.rawValue) detail={\(detail)}")
        }
        let screens = UIScreen.screens
        lines.append("uiscreen count=\(screens.count) isCaptured=\(screens.contains { $0.isCaptured })")
        for line in lines { print("SENTOMARU-LAB " + line) }
        label.text = lines.joined(separator: "\n")
        fflush(stdout)
    }
}

@main
final class LabDelegate: UIResponder, UIApplicationDelegate {
    // iOS 27 refuses an app without the scene lifecycle (runtime issue, SIGTRAP at launch): the window lives in a scene delegate.
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool { true }
}

@objc(LabSceneDelegate)
final class LabSceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = LabController()
        window.makeKeyAndVisible()
        self.window = window
    }
}
