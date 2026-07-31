// Derived from flutter_texture_rgba_renderer 42797e0; modified by RustDesk.
import Cocoa
import CoreFoundation
import FlutterMacOS

public class TextureRgbaRendererPlugin: NSObject, FlutterPlugin {
    private var renderers: [Int64: TextRgba] = [:]
    private let textureRegistry: FlutterTextureRegistry

    init(textureRegistry: FlutterTextureRegistry) {
        self.textureRegistry = textureRegistry
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "texture_rgba_renderer",
            binaryMessenger: registrar.messenger
        )
        let instance = TextureRgbaRendererPlugin(
            textureRegistry: registrar.textures
        )
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    private func arguments(_ call: FlutterMethodCall) -> [String: Any]? {
        call.arguments as? [String: Any]
    }

    private func integer(
        _ arguments: [String: Any]?,
        _ name: String
    ) -> Int64? {
        guard let number = arguments?[name] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(number)
        else {
            return nil
        }
        return number.int64Value
    }

    private func badArguments(_ result: FlutterResult) {
        result(FlutterError(
            code: "bad-arguments",
            message: "Texture arguments are missing or malformed",
            details: nil
        ))
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = arguments(call)
        switch call.method {
        case "createTexture":
            guard let key = integer(args, "key") else {
                return badArguments(result)
            }
            guard renderers[key] == nil else {
                return result(-1)
            }
            let texture = TextRgba.new(registry: textureRegistry)
            guard texture.textureId > 0 else {
                texture.retire()
                return result(-1)
            }
            renderers[key] = texture
            result(texture.textureId)

        case "closeTexture":
            guard let key = integer(args, "key") else {
                return badArguments(result)
            }
            guard let texture = renderers.removeValue(forKey: key) else {
                return result(false)
            }
            let textureId = texture.retire()
            guard textureId > 0 else {
                return result(false)
            }
            textureRegistry.unregisterTexture(textureId)
            result(true)

        case "onRgba":
            guard let key = integer(args, "key"),
                  let widthValue = integer(args, "width"),
                  let heightValue = integer(args, "height"),
                  let strideValue = integer(args, "stride_align"),
                  let width = Int(exactly: widthValue),
                  let height = Int(exactly: heightValue),
                  let strideAlign = Int(exactly: strideValue),
                  let data = args?["data"] as? FlutterStandardTypedData
            else {
                return badArguments(result)
            }
            guard let texture = renderers[key] else {
                return result(false)
            }
            result(texture.markFrameAvaliable(
                data: data.data,
                width: width,
                height: height,
                stride_align: strideAlign
            ))

        case "getTexturePtr":
            guard let key = integer(args, "key") else {
                return badArguments(result)
            }
            guard let texture = renderers[key] else {
                return result(0)
            }
            let address = UInt(
                bitPattern: Unmanaged.passUnretained(texture).toOpaque()
            )
            result(Int64(bitPattern: UInt64(address)))

        default:
            result(FlutterMethodNotImplemented)
        }
    }
}
