#pragma once

namespace x64dbgMCP {

    using namespace System;
    using namespace System::IO;
    using namespace System::Threading;
    using namespace System::Threading::Tasks;
    using namespace System::Collections::Generic;
    using namespace System::ComponentModel;
    using namespace Microsoft::AspNetCore::Builder;
    using namespace Microsoft::Extensions::DependencyInjection;
    using namespace ModelContextProtocol::Server;
    using namespace ModelContextProtocol::Protocol;

    [McpServerToolType]
    public ref class McpTools
    {
    public:
        [McpServerTool, Description("Echoes the input back.")]
        static String^ Echo(String^ message)
        {
            return "echo: " + message;
        }
    };

    public ref class McpServerHost
    {
    private:
        static WebApplication^ _app;
        static Task^ _serverTask;
        static bool _running = false;
        static int _port;
		static String^ _httpUrl;

        static void Log(String^ msg)
        {
            try {
                Diagnostics::Debug::WriteLine(DateTime::Now.ToString("HH:mm:ss.fff") + " " + msg);
            } catch (...) {}
        }

    public:
        static property bool IsRunning { bool get() { return _running; } }

		static bool Start(int port, String^ httpUrl)
        {
            if (_running) return false;
            _port = port;
			_httpUrl = httpUrl ? httpUrl : String::Format("http://localhost:{0}", port);
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
            opts->ServerInfo->Version = "1.0.0";
        }

        static void RunServerEntry()
        {
            try {
                Log("Starting MCP HTTP server on port " + _port);

                auto builder = WebApplication::CreateSlimBuilder();

                // Register MCP server with options
                auto mcpBuilder = McpServerServiceCollectionExtensions::AddMcpServer(
                    builder->Services,
                    gcnew Action<McpServerOptions^>(&ConfigureMcpOptions));

                // Auto-discover tools from [McpServerToolType] classes
                McpServerBuilderExtensions::WithToolsFromAssembly(mcpBuilder);

                // Add HTTP transport (enables Streamable HTTP + legacy SSE)
                HttpMcpServerBuilderExtensions::WithHttpTransport(mcpBuilder, nullptr);

                _app = builder->Build();

                // Listen on loopback only
                _app->Urls->Add(_httpUrl);

                // Map MCP endpoints:
                //   Streamable HTTP: POST /
                //   Legacy SSE:      GET /sse, POST /message
                McpEndpointRouteBuilderExtensions::MapMcp(_app, "");

                Log("WebApplication starting");
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
