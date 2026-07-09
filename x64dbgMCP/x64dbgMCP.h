#pragma once

#include "x64dbgHandler.h"

namespace x64dbgMCP {

    using namespace System;
    using namespace System::IO;
    using namespace System::Threading;
    using namespace System::Threading::Tasks;
    using namespace Microsoft::AspNetCore::Builder;
    using namespace Microsoft::Extensions::DependencyInjection;
    using namespace ModelContextProtocol::Server;
    using namespace ModelContextProtocol::Protocol;

    public ref class McpServerHost
    {
    private:
        static WebApplication^ _app;
        static String^ _httpUrl;
        static Task^ _serverTask;
        static bool _running = false;
        static bool _enableDebugging = false;

        static void Log(String^ message)
        {
            try {
                Diagnostics::Debug::WriteLine(String::Format("{0} {1}", DateTime::Now.ToString("HH:mm:ss.fff"), message));
            } catch (...) {}
        }

    public:
        static property bool IsRunning { bool get() { return _running; } }

        static bool Start(int port)
        {
            return Start(port, nullptr, false);
		}

        static bool Start(int port, String^ httpUrl)
        {
            return Start(port, httpUrl, false);
        }

        static bool Start(int port, String^ httpUrl, bool enableDebugging)
        {
            if (_running) return false;
            _enableDebugging = enableDebugging;
            _httpUrl = httpUrl ? String::Format("http://{0}:{1}", httpUrl, port) : String::Format("http://localhost:{0}", port);
            _serverTask = Task::Run(gcnew Action(&RunServerEntry));
            _running = true;
            return _running;
        }

        static void Stop()
        {
            if (!_running) return;
            try {
                if (_app != nullptr)
                    _app->StopAsync()->GetAwaiter().GetResult();
                if (_serverTask != nullptr)
                    _serverTask->Wait(5000);
            } catch (...) {}
            _running = false;
        }

    private:
        static void ConfigureMcpOptions(McpServerOptions^ opts)
        {
            auto asmName = Reflection::Assembly::GetExecutingAssembly()->GetName();
            opts->ServerInfo = gcnew Implementation();
            opts->ServerInfo->Name = asmName->Name;
            opts->ServerInfo->Version = Helpers::PluginVersion();
        }

        static void RunServerEntry()
        {
            try {
                auto builder = WebApplication::CreateSlimBuilder();

                // Register MCP server with options
                auto mcpBuilder = McpServerServiceCollectionExtensions::AddMcpServer(
                    builder->Services,
                    gcnew Action<McpServerOptions^>(&ConfigureMcpOptions));

                // Register analysis tools (always loaded)
                McpServerBuilderExtensions::WithTools<McpAnalysisTools^>(mcpBuilder);

                // Register MCP resources (read-only, URI-addressable)
                McpServerBuilderExtensions::WithResources<McpResources^>(mcpBuilder);

                // Register debugging tools (on-demand)
                if (_enableDebugging)
                    McpServerBuilderExtensions::WithTools<McpDebuggingTools^>(mcpBuilder);

                // Add HTTP transport (enables Streamable HTTP + legacy SSE)
                HttpMcpServerBuilderExtensions::WithHttpTransport(mcpBuilder, nullptr);

                _app = builder->Build();

                // Listen on loopback only
                _app->Urls->Add(_httpUrl);

                // Map MCP endpoints:
                //   Streamable HTTP: POST /
                //   Legacy SSE:      GET /sse, POST /message
                McpEndpointRouteBuilderExtensions::MapMcp(_app, "");

                Log("WebApplication starting on " + _httpUrl);
                _app->RunAsync()->GetAwaiter().GetResult();
            }
            catch (Exception^ ex) {
                Log("RunServer fatal: " + ex->ToString());
            }
            finally {
                _running = false;
                Log("RunServer exited");
            }
        }
    };
}
