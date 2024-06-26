// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "OTPKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "OTPKit",
            targets: ["OTPKit"]
        )
    ],
    targets: [
        .target(
            name: "OTPKit"
        ),
        .testTarget(
            name: "OTPKitTests",
            dependencies: ["OTPKit"]
        )
    ]
)
