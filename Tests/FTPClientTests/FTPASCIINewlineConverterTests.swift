import Foundation
import Testing
@testable import FTPClientCore

@Test func asciiNewlineConversionHandlesAllChunkBoundaries() {
    let input = Data([65, 13, 10, 66, 10, 67, 13, 68, 13, 0, 69, 13])
    let outputs: [(FTPASCIILineEnding, Data)] = [
        (.unchanged, input),
        (.crlf, Data([65, 13, 10, 66, 13, 10, 67, 13, 10, 68, 13, 0, 69, 13, 10])),
        (.lf, Data([65, 10, 66, 10, 67, 10, 68, 13, 0, 69, 10])),
        (.cr, Data([65, 13, 66, 13, 67, 13, 68, 13, 0, 69, 13]))
    ]
    for (mode, expected) in outputs {
        for split in 0...input.count {
            var converter = FTPASCIINewlineConverter(mode)
            let result = converter.convert(Data(input.prefix(split)), final: false)
                + converter.convert(Data(input.dropFirst(split)), final: true)
            #expect(result == expected)
        }
        var converter = FTPASCIINewlineConverter(mode)
        var result = Data()
        for byte in input { result.append(converter.convert(Data([byte]), final: false)) }
        result.append(converter.convert(Data(), final: true))
        #expect(result == expected)
    }
}