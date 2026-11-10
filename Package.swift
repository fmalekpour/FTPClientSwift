// swift-tools-version: 6.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "FTPClientSwift",
    platforms: [
        .iOS(.v15),
        .macOS(.v14),
        .tvOS(.v17),
        .watchOS(.v10),
    ],
    products: [
        .library(
            name: "FTPClientSwift",
            targets: ["FTPClient"]
        ),
        .library(
            name: "FTPClientFacade",
            targets: ["FTPClientFacade"]
        ),
        .library(
            name: "FTPClientCore",
            targets: ["FTPClientCore"]
        ),
        .library(
            name: "FTPClientSecurity",
            targets: ["FTPClientSecurity"]
        ),
        .library(
            name: "FTPClientSync",
            targets: ["FTPClientSync"]
        ),
    ],
    targets: [
        .target(
            name: "FTPClientCore",
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .target(
            name: "FTPClientSecurity",
            dependencies: ["FTPClientCore"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .target(
            name: "FTPClientSync",
            dependencies: ["FTPClientCore"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .target(
            name: "FTPClientFacade",
            dependencies: ["FTPClientCore", "FTPClientSecurity", "FTPClientSync"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .target(
            name: "FTPClient",
            dependencies: ["FTPClientCore", "FTPClientSecurity", "FTPClientSync", "FTPClientFacade"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
        .testTarget(
            name: "FTPClientTests",
            dependencies: ["FTPClient", "FTPClientFacade", "FTPClientCore", "FTPClientSync"],
            swiftSettings: [
                .enableUpcomingFeature("ApproachableConcurrency"),
            ],
        ),
    ]
)
