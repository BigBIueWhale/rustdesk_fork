#include <d3d11.h>
#include <dwmapi.h>
#include <dxgi1_2.h>
#include <windows.h>
#include <wrl/client.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

using Microsoft::WRL::ComPtr;

constexpr wchar_t kWindowClass[] = L"RustDeskD3D11PreflightWindow";
constexpr UINT kWindowWidth = 400;
constexpr UINT kWindowHeight = 300;

struct Attempt {
  const char* name = nullptr;
  HRESULT window = E_UNEXPECTED;
  HRESULT factory = E_UNEXPECTED;
  HRESULT adapter = E_UNEXPECTED;
  HRESULT device = E_UNEXPECTED;
  HRESULT swap_chain = E_UNEXPECTED;
  HRESULT window_association = E_UNEXPECTED;
  HRESULT back_buffer = E_UNEXPECTED;
  HRESULT render_target = E_UNEXPECTED;
  HRESULT present = E_UNEXPECTED;
  HRESULT dwm_flush = E_UNEXPECTED;
  D3D_FEATURE_LEVEL feature_level = static_cast<D3D_FEATURE_LEVEL>(0);
  UINT adapter_flags = 0;
  std::string adapter_description;
  COLORREF desktop_pixel = CLR_INVALID;
  bool pixel_matches = false;
};

LRESULT CALLBACK WindowProcedure(HWND window,
                                 UINT message,
                                 WPARAM wparam,
                                 LPARAM lparam) {
  if (message == WM_DESTROY) {
    return 0;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

void PumpWindowMessages() {
  MSG message = {};
  while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
}

std::string Hex32(std::uint32_t value) {
  std::ostringstream stream;
  stream << "0x" << std::uppercase << std::hex << std::setw(8)
         << std::setfill('0') << value;
  return stream.str();
}

std::string HResultText(HRESULT value) {
  return Hex32(static_cast<std::uint32_t>(value));
}

std::string WideToUtf8(const wchar_t* value) {
  if (value == nullptr || value[0] == L'\0') {
    return {};
  }
  const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
                                         -1, nullptr, 0, nullptr, nullptr);
  if (needed <= 1) {
    return {};
  }
  std::string result(static_cast<std::size_t>(needed), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
                          result.data(), needed, nullptr, nullptr) == 0) {
    return {};
  }
  result.pop_back();
  return result;
}

std::string JsonString(const std::string& value) {
  std::ostringstream stream;
  stream << '"';
  for (const unsigned char byte : value) {
    switch (byte) {
      case '"':
        stream << "\\\"";
        break;
      case '\\':
        stream << "\\\\";
        break;
      case '\b':
        stream << "\\b";
        break;
      case '\f':
        stream << "\\f";
        break;
      case '\n':
        stream << "\\n";
        break;
      case '\r':
        stream << "\\r";
        break;
      case '\t':
        stream << "\\t";
        break;
      default:
        if (byte < 0x20) {
          stream << "\\u00" << std::uppercase << std::hex << std::setw(2)
                 << std::setfill('0') << static_cast<unsigned int>(byte)
                 << std::dec;
        } else {
          stream << static_cast<char>(byte);
        }
        break;
    }
  }
  stream << '"';
  return stream.str();
}

void RecordAdapter(IDXGIAdapter* adapter, Attempt* attempt) {
  ComPtr<IDXGIAdapter1> adapter1;
  attempt->adapter = adapter->QueryInterface(IID_PPV_ARGS(&adapter1));
  if (FAILED(attempt->adapter)) {
    return;
  }
  DXGI_ADAPTER_DESC1 description = {};
  attempt->adapter = adapter1->GetDesc1(&description);
  if (FAILED(attempt->adapter)) {
    return;
  }
  attempt->adapter_flags = description.Flags;
  attempt->adapter_description = WideToUtf8(description.Description);
}

COLORREF ReadDesktopPixel(HWND window) {
  RECT client = {};
  if (GetClientRect(window, &client) == FALSE) {
    return CLR_INVALID;
  }
  POINT center = {(client.right - client.left) / 2,
                  (client.bottom - client.top) / 2};
  if (ClientToScreen(window, &center) == FALSE) {
    return CLR_INVALID;
  }
  HDC desktop = GetDC(nullptr);
  if (desktop == nullptr) {
    return CLR_INVALID;
  }
  const COLORREF pixel = GetPixel(desktop, center.x, center.y);
  if (ReleaseDC(nullptr, desktop) == 0) {
    return CLR_INVALID;
  }
  return pixel;
}

bool PixelMatches(COLORREF pixel, bool warp) {
  if (pixel == CLR_INVALID) {
    return false;
  }
  const unsigned int red = GetRValue(pixel);
  const unsigned int green = GetGValue(pixel);
  const unsigned int blue = GetBValue(pixel);
  if (warp) {
    return red <= 40 && green >= 220 && blue <= 40;
  }
  return red >= 220 && green <= 40 && blue <= 40;
}

Attempt RunAttempt(bool warp, int x) {
  Attempt attempt;
  attempt.name = warp ? "warp" : "default-adapter";

  HWND window = CreateWindowExW(
      0, kWindowClass,
      warp ? L"RustDesk D3D11 WARP preflight"
           : L"RustDesk D3D11 default-adapter preflight",
      WS_OVERLAPPEDWINDOW, x, 120, static_cast<int>(kWindowWidth),
      static_cast<int>(kWindowHeight), nullptr, nullptr, GetModuleHandleW(nullptr),
      nullptr);
  if (window == nullptr) {
    attempt.window = HRESULT_FROM_WIN32(GetLastError());
    return attempt;
  }
  attempt.window = S_OK;
  ShowWindow(window, SW_SHOW);
  UpdateWindow(window);
  PumpWindowMessages();

  ComPtr<IDXGIFactory1> factory;
  ComPtr<IDXGIAdapter> selected_adapter;
  if (!warp) {
    attempt.factory = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(attempt.factory)) {
      DestroyWindow(window);
      return attempt;
    }
    attempt.adapter = factory->EnumAdapters(0, &selected_adapter);
    if (FAILED(attempt.adapter)) {
      DestroyWindow(window);
      return attempt;
    }
  }

  constexpr D3D_FEATURE_LEVEL feature_levels[] = {
      D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0,
      D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0,
      D3D_FEATURE_LEVEL_9_3};
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  attempt.device = D3D11CreateDevice(
      selected_adapter.Get(),
      warp ? D3D_DRIVER_TYPE_WARP : D3D_DRIVER_TYPE_UNKNOWN, nullptr, 0,
      feature_levels, ARRAYSIZE(feature_levels), D3D11_SDK_VERSION, &device,
      &attempt.feature_level, &context);
  if (FAILED(attempt.device)) {
    DestroyWindow(window);
    return attempt;
  }

  if (warp) {
    ComPtr<IDXGIDevice> dxgi_device;
    attempt.adapter = device.As(&dxgi_device);
    if (SUCCEEDED(attempt.adapter)) {
      attempt.adapter = dxgi_device->GetAdapter(&selected_adapter);
    }
  }
  if (FAILED(attempt.adapter) || selected_adapter == nullptr) {
    DestroyWindow(window);
    return attempt;
  }
  RecordAdapter(selected_adapter.Get(), &attempt);
  if (FAILED(attempt.adapter)) {
    DestroyWindow(window);
    return attempt;
  }

  ComPtr<IDXGIFactory2> factory2;
  attempt.factory = selected_adapter->GetParent(IID_PPV_ARGS(&factory2));
  if (FAILED(attempt.factory)) {
    DestroyWindow(window);
    return attempt;
  }

  DXGI_SWAP_CHAIN_DESC1 description = {};
  description.Width = kWindowWidth;
  description.Height = kWindowHeight;
  description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
  description.Stereo = FALSE;
  description.SampleDesc.Count = 1;
  description.SampleDesc.Quality = 0;
  description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT |
                            DXGI_USAGE_SHADER_INPUT | DXGI_USAGE_BACK_BUFFER;
  description.BufferCount = 1;
  description.Scaling = DXGI_SCALING_STRETCH;
  description.SwapEffect = DXGI_SWAP_EFFECT_SEQUENTIAL;
  description.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
  description.Flags = 0;

  ComPtr<IDXGISwapChain1> swap_chain;
  attempt.swap_chain = factory2->CreateSwapChainForHwnd(
      device.Get(), window, &description, nullptr, nullptr, &swap_chain);
  if (FAILED(attempt.swap_chain)) {
    DestroyWindow(window);
    return attempt;
  }
  attempt.window_association =
      factory2->MakeWindowAssociation(window, DXGI_MWA_NO_ALT_ENTER);

  ComPtr<ID3D11Texture2D> back_buffer;
  attempt.back_buffer =
      swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
  if (FAILED(attempt.back_buffer)) {
    DestroyWindow(window);
    return attempt;
  }
  ComPtr<ID3D11RenderTargetView> render_target;
  attempt.render_target =
      device->CreateRenderTargetView(back_buffer.Get(), nullptr, &render_target);
  if (FAILED(attempt.render_target)) {
    DestroyWindow(window);
    return attempt;
  }

  ID3D11RenderTargetView* target = render_target.Get();
  context->OMSetRenderTargets(1, &target, nullptr);
  const float default_color[4] = {1.0F, 0.0F, 0.0F, 1.0F};
  const float warp_color[4] = {0.0F, 1.0F, 0.0F, 1.0F};
  context->ClearRenderTargetView(render_target.Get(),
                                 warp ? warp_color : default_color);
  attempt.present = swap_chain->Present(1, 0);
  if (SUCCEEDED(attempt.present)) {
    attempt.dwm_flush = DwmFlush();
    Sleep(250);
    PumpWindowMessages();
    attempt.desktop_pixel = ReadDesktopPixel(window);
    attempt.pixel_matches = PixelMatches(attempt.desktop_pixel, warp);
  }
  DestroyWindow(window);
  PumpWindowMessages();
  return attempt;
}

std::string AttemptJson(const Attempt& attempt) {
  std::ostringstream stream;
  stream << "{\"name\":" << JsonString(attempt.name) << ",\"window_hresult\":"
         << JsonString(HResultText(attempt.window))
         << ",\"factory_hresult\":"
         << JsonString(HResultText(attempt.factory))
         << ",\"adapter_hresult\":" << JsonString(HResultText(attempt.adapter))
         << ",\"device_hresult\":" << JsonString(HResultText(attempt.device))
         << ",\"swap_chain_hresult\":"
         << JsonString(HResultText(attempt.swap_chain))
         << ",\"window_association_hresult\":"
         << JsonString(HResultText(attempt.window_association))
         << ",\"back_buffer_hresult\":"
         << JsonString(HResultText(attempt.back_buffer))
         << ",\"render_target_hresult\":"
         << JsonString(HResultText(attempt.render_target))
         << ",\"present_hresult\":" << JsonString(HResultText(attempt.present))
         << ",\"dwm_flush_hresult\":"
         << JsonString(HResultText(attempt.dwm_flush))
         << ",\"feature_level\":"
         << JsonString(Hex32(static_cast<std::uint32_t>(attempt.feature_level)))
         << ",\"adapter_flags\":" << attempt.adapter_flags
         << ",\"adapter_description\":"
         << JsonString(attempt.adapter_description)
         << ",\"desktop_pixel\":"
         << JsonString(Hex32(static_cast<std::uint32_t>(attempt.desktop_pixel)))
         << ",\"pixel_matches\":"
         << (attempt.pixel_matches ? "true" : "false") << '}';
  return stream.str();
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance,
                    HINSTANCE,
                    wchar_t*,
                    int) {
  WNDCLASSEXW window_class = {};
  window_class.cbSize = sizeof(window_class);
  window_class.lpfnWndProc = WindowProcedure;
  window_class.hInstance = instance;
  window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
  window_class.lpszClassName = kWindowClass;
  if (RegisterClassExW(&window_class) == 0) {
    std::cerr << "RegisterClassExW failed: " << GetLastError() << '\n';
    return 1;
  }

  const Attempt default_adapter = RunAttempt(false, 100);
  const Attempt warp = RunAttempt(true, 560);
  std::cout << "{\"format\":\"rustdesk-windows-d3d11-preflight-v1\","
               "\"default_adapter\":"
            << AttemptJson(default_adapter) << ",\"warp\":"
            << AttemptJson(warp) << "}\n";
  std::cout.flush();
  UnregisterClassW(kWindowClass, instance);
  return std::cout.good() ? 0 : 1;
}
