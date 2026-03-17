#pragma once

#include "plugintemplate/pluginmain.h"

namespace x64dbgMCP {

    using namespace System;
    using namespace System::Collections::Generic;
    using namespace System::ComponentModel;
    using namespace ModelContextProtocol::Server;

    public ref class ProjectInfoResult
    {
    public:
        [Description("Plugin Version")]
        property String^ Version
        {
            String^ get()
            {
                return (gcnew System::Version(
                    (PLUGIN_VERSION >> 16) & 0xFF,
                    (PLUGIN_VERSION >> 8) & 0xFF,
                    PLUGIN_VERSION & 0xFF))->ToString();
            }
        }
		[Description("Target Architecture")]
        property String^ Platform {
			String^ get()
			{
#ifdef _WIN64
				return BridgeIsARM64Emulated() ? "arm64" : "x64";
#else
				return "x86";
#endif
			}
        }
		[Description("x64dbg Directory")]
        property String^ X64dbg_dir {
            String^ get() {
                return gcnew String(BridgeUserDirectory());
            }
        }
    };

    [McpServerToolType]
    public ref class McpAnalysisTools
    {
    public:

        // ── Project ──
        [McpServerTool(ReadOnly = true), Description("Get the project information about the currently loaded project.")]
        static auto GetProjectInfo()
        {
            return gcnew ProjectInfoResult();
        }

        // ── Symbol ──

        [McpServerTool(ReadOnly = true), Description("Get the list of all symbols in the debugged module.")]
        static auto GetSymbolList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get symbol information at the specified address.")]
        static auto GetSymbolAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Function ──

        [McpServerTool, Description("Get the list of all recognized functions.")]
        static auto GetFunctionList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get function information at the specified address.")]
        static auto GetFunctionAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Add a function entry at the specified address range.")]
        static auto AddFunction(
            [Description("Start virtual address")] String^ start,
            [Description("End virtual address")] String^ end,
            [Description("Whether this is a manual/user-defined entry")] bool manual,
            [Description("Number of instructions in the function")] int instructionCount)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Delete the function entry at the specified address.")]
        static auto DeleteFunction(
            [Description("Virtual address of the function to delete")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Label ──

        [McpServerTool, Description("Get the list of all labels.")]
        static auto GetLabelList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get label information at the specified address.")]
        static auto GetLabelAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set a label at the specified address.")]
        static auto SetLabel(
            [Description("Virtual address")] String^ addr,
            [Description("Label text")] String^ text,
            [Description("Whether this is a manual/user-defined label")] bool manual,
            [Description("Whether this label is temporary")] bool temporary)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Delete the label at the specified address.")]
        static auto DeleteLabel(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Check if the label at the specified address is temporary.")]
        static auto IsLabelTemporary(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Resolve a label name to its virtual address.")]
        static auto LabelFromString(
            [Description("Label name to resolve")] String^ label)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Comment ──

        [McpServerTool, Description("Get the list of all comments.")]
        static auto GetCommentList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the comment at the specified address.")]
        static auto GetCommentAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set a comment at the specified address.")]
        static auto SetComment(
            [Description("Virtual address")] String^ addr,
            [Description("Comment text")] String^ text,
            [Description("Whether this is a manual/user-defined comment")] bool manual)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Delete the comment at the specified address.")]
        static auto DeleteComment(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Bookmark ──

        [McpServerTool, Description("Get the list of all bookmarks.")]
        static auto GetBookmarkList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get bookmark information at the specified address.")]
        static auto GetBookmarkAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set a bookmark at the specified address.")]
        static auto SetBookmark(
            [Description("Virtual address")] String^ addr,
            [Description("Whether this is a manual/user-defined bookmark")] bool manual)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Delete the bookmark at the specified address.")]
        static auto DeleteBookmark(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Xref (Cross Reference) ──

        [McpServerTool, Description("Get all cross-references to the specified address.")]
        static auto GetXrefs(
            [Description("Target virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Add a cross-reference from one address to another.")]
        static auto AddXref(
            [Description("Target virtual address")] String^ addr,
            [Description("Source virtual address of the reference")] String^ from)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }
        [McpServerTool, Description("Get the number of cross-references at the specified address.")]
        static auto GetXrefCountAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the type of cross-reference at the specified address (0=NONE, 1=DATA, 2=JMP, 3=CALL).")]
        static auto GetXrefTypeAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Module ──

        [McpServerTool, Description("Get the list of all loaded modules.")]
        static auto GetModuleList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get information about the main (debugged) module.")]
        static auto GetMainModuleInfo()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get module information by virtual address.")]
        static auto GetModuleByAddr(
            [Description("Virtual address within the module")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get module information by module name.")]
        static auto GetModuleByName(
            [Description("Module name (e.g. kernel32.dll)")] String^ name)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the section list of the main module.")]
        static auto GetMainModuleSectionList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the section list of a module by virtual address.")]
        static auto GetSectionListByAddr(
            [Description("Virtual address within the module")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the section list of a module by name.")]
        static auto GetSectionListByName(
            [Description("Module name")] String^ name)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the export table of a module by virtual address.")]
        static auto GetExports(
            [Description("Virtual address within the module")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the import table of a module by virtual address.")]
        static auto GetImports(
            [Description("Virtual address within the module")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Memory (read-only) ──

        [McpServerTool, Description("Check if the specified address is a valid pointer in the debugged process.")]
        static auto IsValidPtr(
            [Description("Virtual address to check")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the memory map of the debugged process.")]
        static auto GetMemoryMaps()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the base address of the memory region containing the specified address.")]
        static auto GetMemoryBase(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the size of the memory region containing the specified address.")]
        static auto GetMemorySize(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Read memory from the debugged process. Returns base64-encoded bytes.")]
        static auto MemoryRead(
            [Description("Virtual address to read from")] String^ addr,
            [Description("Number of bytes to read")] int size)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Thread (query only) ──

        [McpServerTool, Description("Get the list of all threads in the debugged process.")]
        static auto GetThreadList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Disassemble ──

        [McpServerTool, Description("Disassemble instructions starting at the specified address. Returns up to 'count' instructions (max 20).")]
        static auto Disassemble(
            [Description("Virtual address to start disassembly")] String^ addr,
            [Description("Number of instructions to disassemble (max 20)")] int count)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Pattern ──

        [McpServerTool, Description("Search for a byte pattern in the debugged module. Pattern format: \"AA BB ?? CC\".")]
        static auto FindPattern(
            [Description("Byte pattern with ?? as wildcard (e.g. \"48 89 5C 24 ?? 57\")")] String^ pattern)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Misc ──

        [McpServerTool, Description("Evaluate a x64dbg expression string and return the result as an address.")]
        static auto ParseExpression(
            [Description("Expression string (e.g. \"kernel32:CreateFileW\", \"peb()\", \"mem.base(cip)\")")] String^ expression)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Resolve a label name to its virtual address.")]
        static auto ResolveLabel(
            [Description("Label or API name to resolve (e.g. \"LoadLibraryA\")")] String^ label)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the string (if any) at the specified address in the debugged process.")]
        static auto GetStringAt(
            [Description("Virtual address to query")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

    };

    [McpServerToolType]
    public ref class McpDebuggingTools
    {
    public:

        // ── Debug Control ──

        [McpServerTool, Description("Check if the debugger is currently attached/debugging.")]
            static auto IsDebugging()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Check if the debugged process is currently running (not paused).")]
        static auto IsRunning()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Run/continue the debugged process.")]
        static auto DebugRun()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Pause the debugged process.")]
        static auto DebugPause()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Stop debugging (detach/terminate).")]
        static auto DebugStop()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Restart the debugged process.")]
        static auto DebugRestart()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Step into the next instruction.")]
        static auto StepInto()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Step over the next instruction (skip calls).")]
        static auto StepOver()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Step out of the current function.")]
        static auto StepOut()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Execute a x64dbg command synchronously.")]
        static auto RunCommand(
            [Description("x64dbg command string")] String^ command)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Breakpoint ──

        [McpServerTool, Description("Get the list of breakpoints. bpxtype: 0=all, 1=normal, 2=hardware, 4=memory.")]
        static auto GetBreakpointList(
            [Description("Breakpoint type filter (0=all, 1=normal, 2=hardware, 4=memory)")] int bpxtype)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set a software breakpoint at the specified address.")]
        static auto SetBreakpoint(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Delete the software breakpoint at the specified address.")]
        static auto DeleteBreakpoint(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Disable the breakpoint at the specified address.")]
        static auto DisableBreakpoint(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set a hardware breakpoint at the specified address. type: 0=access, 1=write, 2=execute.")]
        static auto SetHardwareBreakpoint(
            [Description("Virtual address")] String^ addr,
            [Description("Hardware breakpoint type (0=access, 1=write, 2=execute)")] int type)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Delete the hardware breakpoint at the specified address.")]
        static auto DeleteHardwareBreakpoint(
            [Description("Virtual address")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Register ──

        [McpServerTool, Description("Get the value of a CPU flag by index.")]
        static auto GetFlag(
            [Description("Flag index (0=ZF, 1=OF, 2=CF, 3=PF, 4=SF, 5=TF, 6=AF, 7=DF, 8=IF)")] int flag)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set the value of a CPU flag by index.")]
        static auto SetFlag(
            [Description("Flag index (0=ZF, 1=OF, 2=CF, 3=PF, 4=SF, 5=TF, 6=AF, 7=DF, 8=IF)")] int flag,
            [Description("Flag value")] bool value)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get the value of a register by index.")]
        static auto GetRegister(
            [Description("Register enum index")] int reg)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set the value of a register by index.")]
        static auto SetRegister(
            [Description("Register enum index")] int reg,
            [Description("Value to set")] String^ value)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Get a full dump of all registers.")]
        static auto GetRegisterDump()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Memory ──

        [McpServerTool, Description("Write memory to the debugged process.")]
        static auto MemoryWrite(
            [Description("Virtual address to write to")] String^ addr,
            [Description("Base64-encoded bytes to write")] String^ base64Data)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Allocate memory in the debugged process.")]
        static auto MemoryAlloc(
            [Description("Desired size in bytes")] int size,
            [Description("Preferred virtual address (0 for any)")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Free allocated memory in the debugged process.")]
        static auto MemoryFree(
            [Description("Virtual address to free")] String^ addr)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Stack ──

        [McpServerTool, Description("Get the call stack of the specified thread.")]
        static auto GetCallStack(
            [Description("Thread ID")] int threadId)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Thread ──

        [McpServerTool, Description("Set the name of a thread.")]
        static auto SetThreadName(
            [Description("Thread ID")] int threadId,
            [Description("New thread name")] String^ name)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Set the active thread for debugging.")]
        static auto SetActiveThread(
            [Description("Thread ID")] int threadId)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Suspend a thread.")]
        static auto SuspendThread(
            [Description("Thread ID")] int threadId)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Resume a suspended thread.")]
        static auto ResumeThread(
            [Description("Thread ID")] int threadId)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Create a new thread at the specified entry point.")]
        static auto CreateThread(
            [Description("Entry point virtual address")] String^ entry,
            [Description("Argument to pass to the thread")] String^ arg)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Assemble ──

        [McpServerTool, Description("Assemble a single instruction at the specified address.")]
        static auto Assemble(
            [Description("Virtual address to assemble at")] String^ addr,
            [Description("Assembly instruction (e.g. \"nop\", \"mov eax, 1\")")] String^ instruction)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── GUI ──

        //[McpServerTool, Description("Show a message box in x64dbg.")]
        static auto GuiMessage(
            [Description("Message text")] String^ message)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        //[McpServerTool, Description("Show a Yes/No dialog in x64dbg. Returns true for Yes.")]
        static auto GuiMessageYesNo(
            [Description("Question text")] String^ message)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        //[McpServerTool, Description("Refresh all x64dbg GUI views.")]
        static auto GuiRefresh()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        //[McpServerTool, Description("Focus a specific x64dbg window. win: 0=Disassembly, 1=Dump, 2=Stack, 3=Graph, 4=MemMap, 5=SymMod, 6=Threads.")]
        static auto GuiFocusView(
            [Description("Window type (0=Disassembly, 1=Dump, 2=Stack, 3=Graph, 4=MemMap, 5=SymMod, 6=Threads)")] int window)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        //[McpServerTool, Description("Set the selection range in a x64dbg window.")]
        static auto GuiSelectionSet(
            [Description("Window type")] int window,
            [Description("Start virtual address")] String^ start,
            [Description("End virtual address")] String^ end)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        //[McpServerTool, Description("Get the current selection range in a x64dbg window. Returns [start, end].")]
        static auto GuiSelectionGet(
            [Description("Window type")] int window)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Script ──
        /*
        [McpServerTool, Description("Load a script file into the x64dbg script engine.")]
        static auto ScriptLoad(
            [Description("Path to the script file")] String^ filename)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Unload the currently loaded script.")]
        static auto ScriptUnload()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Run the loaded script from the specified line.")]
        static auto ScriptRun(
            [Description("Line number to start execution from")] int destLine)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Abort the currently running script.")]
        static auto ScriptAbort()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        [McpServerTool, Description("Execute a command in the x64dbg script engine.")]
        static auto ScriptCmdExec(
            [Description("Script command to execute")] String^ command)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }
        */
        // ── Logging ──

        [McpServerTool, Description("Write a line to the x64dbg log window.")]
        static auto LogPuts(
            [Description("Text to log")] String^ text)
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

        // ── Watch ──

        //[McpServerTool, Description("Get the list of all watch expressions.")]
        static auto GetWatchList()
        {
            // TODO: 
            throw gcnew NotImplementedException();
        }

    };
}
