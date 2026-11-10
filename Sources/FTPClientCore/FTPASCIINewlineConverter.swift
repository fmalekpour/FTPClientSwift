import Foundation

/// Normalizes CRLF, bare CR, and bare LF while retaining a CR between chunks.
/// NVT's CR NUL sequence is preserved because it represents a literal CR.
struct FTPASCIINewlineConverter {
    let mode: FTPASCIILineEnding
    private var pendingCR = false

    init(_ mode: FTPASCIILineEnding) { self.mode = mode }

    mutating func convert(_ input: Data, final: Bool) -> Data {
        guard mode != .unchanged else { return input }
        var result = Data()
        func newline() {
            switch mode {
            case .crlf: result.append(contentsOf: [13, 10])
            case .lf: result.append(10)
            case .cr: result.append(13)
            case .unchanged: break
            }
        }
        for byte in input {
            if pendingCR {
                pendingCR = false
                if byte == 0 {
                    result.append(contentsOf: [13, 0])
                    continue
                }
                newline()
                if byte == 10 { continue }
            }
            if byte == 13 { pendingCR = true }
            else if byte == 10 { newline() }
            else { result.append(byte) }
        }
        if final && pendingCR { pendingCR = false; newline() }
        return result
    }
}