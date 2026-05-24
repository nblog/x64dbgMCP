#ifdef _WIN64
#pragma comment(lib, "pluginsdk/x64dbg.lib")
#pragma comment(lib, "pluginsdk/x64bridge.lib")
#pragma comment(lib, "pluginsdk/lz4/lz4_x64.lib")
// #pragma comment(lib, "pluginsdk/jansson/jansson_x64.lib")
// #pragma comment(lib, "pluginsdk/XEDParse/XEDParse_x64.lib")
#else
#pragma comment(lib, "pluginsdk/x32dbg.lib")
#pragma comment(lib, "pluginsdk/x32bridge.lib")
#pragma comment(lib, "pluginsdk/lz4/lz4_x86.lib")
// #pragma comment(lib, "pluginsdk/jansson/jansson_x86.lib")
// #pragma comment(lib, "pluginsdk/XEDParse/XEDParse_x86.lib")
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "plugin.h"
#include "../x64dbgMCP.h"

// References:
// - https://help.x64dbg.com/en/latest/developers/plugins/index.html

// mcp.start [port=3001],[host=localhost] - start MCP server
//   port : TCP port to listen on (1025-49150)
//   host : bind address; pass 0.0.0.0 to expose beyond loopback (default localhost)
static bool cbMcpStart(int argc, char** argv)
{
    if (x64dbgMCP::McpServerHost::IsRunning) {
        dputs("MCP server already running");
        return false;
    }

    int port = 3001;
    if (argc >= 2 && argv[1] && argv[1][0]) {
        int p = atoi(argv[1]);
        if (p > 1024 && p <= 49151) port = p;
        else dprintf("invalid port '%s', using default %d\n", argv[1], port);
    }

    System::String^ host = nullptr;
    if (argc >= 3 && argv[2] && argv[2][0])
        host = gcnew System::String(argv[2]);

    if (x64dbgMCP::McpServerHost::Start(port, host)) {
        dprintf("MCP server started on %s:%d\n", host ? argv[2] : "localhost", port);
        return true;
    }

    dputs("Failed to start MCP server");
    return false;
}

// mcp.stop - stop MCP server
static bool cbMcpStop(int argc, char** argv)
{
    if (!x64dbgMCP::McpServerHost::IsRunning) {
        dputs("MCP server is not running");
        return false;
    }

    x64dbgMCP::McpServerHost::Stop();
    dputs("MCP server stopped");
    return true;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    _plugin_registercommand(pluginHandle, "mcp.start", cbMcpStart, false);
    _plugin_registercommand(pluginHandle, "mcp.stop", cbMcpStop, false);

    // Return false to cancel loading the plugin.
    return true;
}

// Deinitialize your plugin data here.
void pluginStop()
{
    x64dbgMCP::McpServerHost::Stop();
    dprintf("pluginStop(pluginHandle: %d)\n", pluginHandle);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup()
{
    // Prefix of the functions to call here: _plugin_menu

    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}
