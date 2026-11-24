// swift-tools-version: 5.10
// Swift API of the Open AdBlock core for macOS (and later iOS) hosts.
// Run scripts/build-apple.sh first: it produces Artifacts/COpenAdBlock.xcframework.
import PackageDescription

let package = Package(
    name: "OpenAdBlockCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "OpenAdBlockCore", targets: ["OpenAdBlockCore"])],
    targets: [
        .binaryTarget(name: "COpenAdBlock", path: "Artifacts/COpenAdBlock.xcframework"),
        .target(
            name: "OpenAdBlockCore",
            dependencies: ["COpenAdBlock"],
            linkerSettings: [.linkedLibrary("iconv")]
        ),
        .testTarget(name: "OpenAdBlockCoreTests", dependencies: ["OpenAdBlockCore"]),
    ]
)
