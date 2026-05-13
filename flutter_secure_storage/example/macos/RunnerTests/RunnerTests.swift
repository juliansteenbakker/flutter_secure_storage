import Cocoa
import FlutterMacOS
import XCTest

import flutter_secure_storage_darwin

// Tests for FlutterSecureStorageDarwinPlugin's event-channel behaviour around
// protected-data availability.  The applicationProtectedDataDidBecomeAvailable
// and applicationProtectedDataWillBecomeUnavailable delegate callbacks were
// present in the archived separate iOS/macOS plugins but were accidentally
// omitted when the two were merged into the unified darwin package.
// See https://github.com/juliansteenbakker/flutter_secure_storage/issues/1000
class RunnerTests: XCTestCase {

    // MARK: - Selector existence (fail fast if the method is simply missing)

    @available(macOS 12.0, *)
    func testPluginImplementsProtectedDataAvailableCallback() {
        let plugin = FlutterSecureStorageDarwinPlugin()
        XCTAssertTrue(
            plugin.responds(to: NSSelectorFromString("applicationProtectedDataDidBecomeAvailable:")),
            "Plugin must implement applicationProtectedDataDidBecomeAvailable to emit events on the stream channel"
        )
    }

    @available(macOS 12.0, *)
    func testPluginImplementsProtectedDataWillBecomeUnavailableCallback() {
        let plugin = FlutterSecureStorageDarwinPlugin()
        XCTAssertTrue(
            plugin.responds(to: NSSelectorFromString("applicationProtectedDataWillBecomeUnavailable:")),
            "Plugin must implement applicationProtectedDataWillBecomeUnavailable to emit events on the stream channel"
        )
    }

    // MARK: - Event-sink behaviour

    @available(macOS 12.0, *)
    func testProtectedDataAvailableEmitsTrueOnSink() {
        let plugin = FlutterSecureStorageDarwinPlugin()
        var received: Any? = "not called"
        let sink: FlutterEventSink = { event in received = event }

        _ = plugin.onListen(withArguments: nil, eventSink: sink)

        let sel = NSSelectorFromString("applicationProtectedDataDidBecomeAvailable:")
        if plugin.responds(to: sel) {
            plugin.perform(sel, with: NSNotification(
                name: Notification.Name("applicationProtectedDataDidBecomeAvailable"),
                object: nil))
        }

        XCTAssertEqual(received as? Bool, true,
            "applicationProtectedDataDidBecomeAvailable must call eventSink(true)")
    }

    @available(macOS 12.0, *)
    func testProtectedDataWillBecomeUnavailableEmitsFalseOnSink() {
        let plugin = FlutterSecureStorageDarwinPlugin()
        var received: Any? = "not called"
        let sink: FlutterEventSink = { event in received = event }

        _ = plugin.onListen(withArguments: nil, eventSink: sink)

        let sel = NSSelectorFromString("applicationProtectedDataWillBecomeUnavailable:")
        if plugin.responds(to: sel) {
            plugin.perform(sel, with: NSNotification(
                name: Notification.Name("applicationProtectedDataWillBecomeUnavailable"),
                object: nil))
        }

        XCTAssertEqual(received as? Bool, false,
            "applicationProtectedDataWillBecomeUnavailable must call eventSink(false)")
    }

    @available(macOS 12.0, *)
    func testProtectedDataEventWithNoListenerDoesNotCrash() {
        // Regression: calling the delegate with no active stream listener must
        // not crash (nil-sink guard must be in place).
        let plugin = FlutterSecureStorageDarwinPlugin()
        let sel = NSSelectorFromString("applicationProtectedDataDidBecomeAvailable:")
        if plugin.responds(to: sel) {
            plugin.perform(sel, with: NSNotification(
                name: Notification.Name("applicationProtectedDataDidBecomeAvailable"),
                object: nil))
        }
    }

    @available(macOS 12.0, *)
    func testNoEventsEmittedAfterOnCancel() {
        let plugin = FlutterSecureStorageDarwinPlugin()
        var received: Any? = nil
        let sink: FlutterEventSink = { event in received = event }

        _ = plugin.onListen(withArguments: nil, eventSink: sink)
        _ = plugin.onCancel(withArguments: nil)

        let sel = NSSelectorFromString("applicationProtectedDataDidBecomeAvailable:")
        if plugin.responds(to: sel) {
            plugin.perform(sel, with: NSNotification(
                name: Notification.Name("applicationProtectedDataDidBecomeAvailable"),
                object: nil))
        }

        XCTAssertNil(received,
            "No events should be emitted after the stream listener has been cancelled")
    }
}
