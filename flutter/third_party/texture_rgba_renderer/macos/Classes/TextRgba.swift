// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
import CoreVideo
import FlutterMacOS
import Foundation

@objc public class TextRgba: NSObject, FlutterTexture {
    public private(set) var textureId: Int64 = 0

    private var registry: FlutterTextureRegistry?
    private var data: CVPixelBuffer?
    private var framePending = false
    private let queue = DispatchQueue(label: "org.rustdesk.texture-rgba")

    public static func new(registry: FlutterTextureRegistry) -> TextRgba {
        let texture = TextRgba()
        texture.registry = registry
        texture.textureId = registry.register(texture)
        return texture
    }

    public func copyPixelBuffer() -> Unmanaged<CVPixelBuffer>? {
        queue.sync {
            guard let data else {
                return nil
            }
            framePending = false
            return Unmanaged.passRetained(data)
        }
    }

    public func retire() -> Int64 {
        queue.sync {
            let retiredId = textureId
            textureId = 0
            registry = nil
            data = nil
            framePending = false
            return retiredId
        }
    }

    private func checkedSourceLayout(
        width: Int,
        height: Int,
        strideAlign: Int
    ) -> (rowBytes: Int, sourceRowBytes: Int, sourceSize: Int)? {
        guard width > 0, height > 0, strideAlign >= 0 else {
            return nil
        }
        let (rowBytes, rowOverflow) = width.multipliedReportingOverflow(by: 4)
        guard !rowOverflow else {
            return nil
        }

        let sourceRowBytes: Int
        if strideAlign <= 1 {
            sourceRowBytes = rowBytes
        } else {
            guard strideAlign.nonzeroBitCount == 1 else {
                return nil
            }
            let (rounded, roundOverflow) =
                rowBytes.addingReportingOverflow(strideAlign - 1)
            guard !roundOverflow else {
                return nil
            }
            sourceRowBytes = rounded & ~(strideAlign - 1)
        }

        let (sourceSize, sizeOverflow) =
            sourceRowBytes.multipliedReportingOverflow(by: height)
        guard !sizeOverflow else {
            return nil
        }
        return (rowBytes, sourceRowBytes, sourceSize)
    }

    private func markFrameAvailable(
        buffer: UnsafePointer<UInt8>,
        length: Int,
        width: Int,
        height: Int,
        strideAlign: Int
    ) -> Bool {
        guard textureId > 0, let registry,
              let layout = checkedSourceLayout(
                  width: width,
                  height: height,
                  strideAlign: strideAlign
              ),
              length >= layout.sourceSize
        else {
            return false
        }

        var pixelBuffer: CVPixelBuffer?
        let attributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String:
                kCVPixelFormatType_32BGRA,
            kCVPixelBufferMetalCompatibilityKey as String: true,
            kCVPixelBufferOpenGLCompatibilityKey as String: true,
            kCVPixelBufferBytesPerRowAlignmentKey as String: 64,
        ]
        guard CVPixelBufferCreate(
            kCFAllocatorDefault,
            width,
            height,
            kCVPixelFormatType_32BGRA,
            attributes as CFDictionary,
            &pixelBuffer
        ) == kCVReturnSuccess, let pixelBuffer else {
            return false
        }
        guard CVPixelBufferLockBaseAddress(pixelBuffer, []) ==
                kCVReturnSuccess else {
            return false
        }
        defer {
            CVPixelBufferUnlockBaseAddress(pixelBuffer, [])
        }
        guard let destination = CVPixelBufferGetBaseAddress(pixelBuffer) else {
            return false
        }
        let destinationRowBytes = CVPixelBufferGetBytesPerRow(pixelBuffer)
        guard destinationRowBytes >= layout.rowBytes else {
            return false
        }

        for row in 0..<height {
            memcpy(
                destination.advanced(by: row * destinationRowBytes),
                buffer.advanced(by: row * layout.sourceRowBytes),
                layout.rowBytes
            )
        }
        data = pixelBuffer
        let notificationNeeded = !framePending
        framePending = true
        if notificationNeeded {
            registry.textureFrameAvailable(textureId)
        }
        return true
    }

    @objc public func markFrameAvaliableRaw(
        buffer: UnsafePointer<UInt8>,
        len: Int,
        width: Int,
        height: Int,
        stride_align: Int
    ) -> Bool {
        queue.sync {
            markFrameAvailable(
                buffer: buffer,
                length: len,
                width: width,
                height: height,
                strideAlign: stride_align
            )
        }
    }

    @objc public func markFrameAvaliable(
        data: Data,
        width: Int,
        height: Int,
        stride_align: Int
    ) -> Bool {
        data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else {
                return false
            }
            return markFrameAvaliableRaw(
                buffer: baseAddress.assumingMemoryBound(to: UInt8.self),
                len: data.count,
                width: width,
                height: height,
                stride_align: stride_align
            )
        }
    }
}
