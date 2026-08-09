#pragma once

#include "x64dbgHandler.h"

namespace x64dbgMCP {

    using namespace System;
    using namespace System::IO;
    using namespace System::Threading;
    using namespace System::Threading::Tasks;
    using namespace Microsoft::AspNetCore::Builder;
    using namespace Microsoft::Extensions::DependencyInjection;
    using namespace Microsoft::Extensions::Hosting;
    using namespace ModelContextProtocol::Server;
    using namespace ModelContextProtocol::Protocol;

    public ref class McpServerHost
    {
    private:
        static WebApplication^ _app;
        static String^ _httpUrl;
        static Task^ _serverTask;
        static TaskCompletionSource<bool>^ _startupCompletion;
        static bool _running = false;
        static bool _starting = false;
        static bool _enableDebugging = false;

        static void Log(String^ message)
        {
            try {
                Diagnostics::Debug::WriteLine(String::Format("{0} {1}", DateTime::Now.ToString("HH:mm:ss.fff"), message));
            } catch (...) {}
        }

    public:
        static property bool IsRunning { bool get() { return _running || _starting; } }

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
            if (_running || _starting) return false;
            _starting = true;
            _enableDebugging = enableDebugging;
            _httpUrl = httpUrl ? String::Format("http://{0}:{1}", httpUrl, port) : String::Format("http://localhost:{0}", port);
            _startupCompletion = gcnew TaskCompletionSource<bool>(TaskCreationOptions::RunContinuationsAsynchronously);

            try {
                _serverTask = Task::Run(gcnew Action(&RunServerEntry));
                bool started = _startupCompletion->Task->GetAwaiter().GetResult();
                _starting = false;
                return started;
            }
            catch (Exception^ ex) {
                // The startup signal is completed from the server task's catch block.
                // Wait for its finally block before allowing a retry to reuse static state.
                try {
                    if (_serverTask != nullptr)
                        _serverTask->Wait();
                } catch (...) {}
                _starting = false;
                Log("Start failed: " + ex->ToString());
                return false;
            }
        }

        static void Stop()
        {
            if (!_running && !_starting) return;
            bool stopped = _serverTask == nullptr || _serverTask->IsCompleted;
            try {
                if (_app != nullptr)
                    _app->StopAsync()->GetAwaiter().GetResult();
                if (_serverTask != nullptr)
                    stopped = _serverTask->Wait(5000);
            } catch (Exception^ ex) {
                stopped = _serverTask == nullptr || _serverTask->IsCompleted;
                Log("Stop failed: " + ex->ToString());
            }

            if (stopped)
            {
                _running = false;
                _starting = false;
            }
            else
            {
                Log("Stop timed out; server remains active until the background task exits");
            }
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
            auto startupCompletion = _startupCompletion;
            String^ httpUrl = _httpUrl;
            bool enableDebugging = _enableDebugging;

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
                if (enableDebugging)
                    McpServerBuilderExtensions::WithTools<McpDebuggingTools^>(mcpBuilder);

                // Add HTTP transport (enables Streamable HTTP + legacy SSE)
                HttpMcpServerBuilderExtensions::WithHttpTransport(mcpBuilder, nullptr);

                _app = builder->Build();

                // Bind the configured host; the command defaults it to localhost.
                _app->Urls->Add(httpUrl);

                // Map MCP endpoints:
                //   Streamable HTTP: POST /
                //   Legacy SSE:      GET /sse, POST /message
                McpEndpointRouteBuilderExtensions::MapMcp(_app, "");

                Log("WebApplication starting on " + httpUrl);
                _app->StartAsync()->GetAwaiter().GetResult();
                _running = true;
                _starting = false;
                startupCompletion->TrySetResult(true);
                HostingAbstractionsHostExtensions::WaitForShutdownAsync(
                    _app,
                    CancellationToken::None)->GetAwaiter().GetResult();
            }
            catch (Exception^ ex) {
                if (startupCompletion != nullptr && !startupCompletion->Task->IsCompleted)
                    startupCompletion->TrySetException(ex);
                Log("RunServer fatal: " + ex->ToString());
            }
            finally {
                if (startupCompletion != nullptr && !startupCompletion->Task->IsCompleted)
                    startupCompletion->TrySetResult(false);
                _running = false;
                _starting = false;
                _app = nullptr;
                Log("RunServer exited");
            }
        }
    };
}
