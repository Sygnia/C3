#include "Stdafx.h"
#include "Pipe.h"
#include "Common/FSecure/CppTools/ScopeGuard.h"

#include "sddl.h"
#pragma comment(lib, "advapi32.lib")

namespace
{
	BOOL CreateDACL(SECURITY_ATTRIBUTES* pSA)
	{
		pSA->nLength = sizeof(SECURITY_ATTRIBUTES);
		pSA->bInheritHandle = FALSE;

		const wchar_t* szSD = OBF(
			L"D:"       // Discretionary ACL
			"(D;OICI;GA;;;BG)"		// Deny access to
									// built-in guests
			"(D;OICI;GA;;;AN)"		// Deny access to
									// anonymous logon
			"(A;OICI;GRGW;;;AU)"	// Allow
									// read/write
									// to authenticated
									// users
			"(A;OICI;GA;;;BA)");	// Allow full control
									 // to administrators

		if (NULL == pSA)
			return FALSE;

		return ConvertStringSecurityDescriptorToSecurityDescriptorW(
			szSD,
			SDDL_REVISION_1,
			&(pSA->lpSecurityDescriptor),
			NULL);
	}

	BOOL FreeDACL(SECURITY_ATTRIBUTES* pSA)
	{
		return NULL == LocalFree(pSA->lpSecurityDescriptor);
	}

	std::unique_ptr<SECURITY_ATTRIBUTES, std::function<void(SECURITY_ATTRIBUTES*)>> g_SecurityAttributes =
	{
		[]() {auto ptr = new SECURITY_ATTRIBUTES; CreateDACL(ptr); return ptr; }(),
		[](SECURITY_ATTRIBUTES* ptr) {FreeDACL(ptr);  delete ptr; }
	};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::WinTools::WritePipe::WritePipe(ByteView pipename)
	:
	m_PipeName(OBF(R"(\\.\pipe\)") + std::string{ pipename }),
	m_Pipe([&]()
{
	auto handle = CreateNamedPipeA(m_PipeName.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 512, 102400, 0, g_SecurityAttributes.get());
	if (!handle)
		throw std::runtime_error{ OBF("Creating pipe failed:") + m_PipeName };

	return handle;
}(), [](void* data)
{
	CloseHandle(data);
})
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::WinTools::WritePipe::Write(ByteView data)
{
	if (data.size() > std::numeric_limits<uint32_t>::max())
		throw std::runtime_error{ OBF("Write error, too much data.") };

	ConnectNamedPipe(m_Pipe.get(), nullptr);
	SCOPE_GUARD( DisconnectNamedPipe(m_Pipe.get()); );
	DWORD written;
	uint32_t len = static_cast<uint32_t>(data.size());
	WriteFile(m_Pipe.get(), &len, sizeof(len), nullptr, nullptr);
	WriteFile(m_Pipe.get(), data.data(), len, &written, nullptr);
	if (written != data.size())
		throw std::runtime_error{ OBF("Write pipe failed ") };

	FlushFileBuffers(m_Pipe.get());

	return data.size();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::WinTools::ReadPipe::ReadPipe(ByteView pipename)
	: m_PipeName(OBF(R"(\\.\pipe\)") + std::string{ pipename })
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::WinTools::ReadPipe::Read()
{
	HANDLE pipe = CreateFileA(m_PipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, g_SecurityAttributes.get(), OPEN_EXISTING, 0, NULL);
	if (pipe == INVALID_HANDLE_VALUE)
		return {};

	SCOPE_GUARD( CloseHandle(pipe); );

	DWORD chunkSize;
	uint32_t pipeBufferSize = 512u;
	uint32_t dataSize = 0u;
	if (!ReadFile(pipe, static_cast<LPVOID>(&dataSize), 4, nullptr, nullptr))
		throw std::runtime_error{ OBF("Unable to read data") };

	ByteVector buffer;
	buffer.resize(dataSize);

	DWORD read = 0;
	while (read < dataSize)
	{
		if (!ReadFile(pipe, (LPVOID)&buffer[read], static_cast<DWORD>((pipeBufferSize < (dataSize - read)) ? pipeBufferSize : (dataSize - read)), &chunkSize, nullptr) || !chunkSize)
			throw std::runtime_error{ OBF("Unable to read data") };

		read += chunkSize;
	}

	return buffer;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::WinTools::DuplexPipe::DuplexPipe(ByteView inputPipeName, ByteView outputPipeName)
	: m_InputPipe(inputPipeName), m_OutputPipe(outputPipeName)
{
}



/* write a frame to a file */
void write_frame(HANDLE my_handle, char* buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(my_handle, (void*)& length, 4, &wrote, NULL);
	WriteFile(my_handle, buffer, length, &wrote, NULL);
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::WinTools::DuplexPipe::Read()
{
	return m_InputPipe.Read();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::WinTools::DuplexPipe::Write(ByteView data)
{
	return m_OutputPipe.Write(data);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::WinTools::AlternatingPipe::AlternatingPipe(ByteView pipename)
	: m_PipeName(OBF("\\\\.\\pipe\\") + std::string{pipename})
	, m_Pipe([&]() {auto tmp = CreateFileA(m_PipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, g_SecurityAttributes.get(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL); return tmp == INVALID_HANDLE_VALUE ? nullptr : tmp; }())
	, m_Event(CreateEvent(nullptr, false, true, nullptr))
{
	if (!m_Pipe)
		throw std::runtime_error{ OBF("Couldn't open named") };

	if (!m_Event)
		throw std::runtime_error{ OBF("Couldn't create synchronization event") };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::WinTools::AlternatingPipe::ReadCov()
{
	DWORD temp = 0, total = 0, result = 0, available = 0;
	// Removed because double pipes don't require it and it causes a deadlock.
	/*if (WaitForSingleObject(m_Event.get(), 0) != WAIT_OBJECT_0)
		return{};*/

	for (int i = 0; i < 2; i++) {
		result = PeekNamedPipe(m_Pipe.get(), NULL, NULL, NULL, &available, NULL);
		if (available > 0)
			break;
		Sleep(1000);
	}
	if (available == 0)
		return {};
	//The SMB Grunt writes the size of the chunk in a loop like the below, mimic that here.
	BYTE size[4] = { 0 };
	int totalReadBytes = 0;
	for(int i = 0; i < 4; i++)
		ReadFile(m_Pipe.get(), size + i, 1, &temp, NULL);


	DWORD32 len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];

	ByteVector buffer;
	buffer.resize(len);

	//Now read the actual data
	DWORD read = 0;
	temp = 0;
	while (total < len) {
		bool didRead = ReadFile(m_Pipe.get(), (LPVOID)& buffer[read], len - total, &temp,
			NULL);
		total += temp;
		read += temp;
	}
	return buffer;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::WinTools::AlternatingPipe::Read()
{
	// Wait other side to read the pipe.
	if (WaitForSingleObject(m_Event.get(), 0) != WAIT_OBJECT_0)
		return{};

	// Read four bytes and find the length of the next chunk of data.
	DWORD chunkLength = 0, bytesReadCurrent = 0;
	if (!ReadFile(m_Pipe.get(), &chunkLength, 4, &bytesReadCurrent, nullptr))
		throw std::runtime_error{ OBF("Couldn't read from Pipe: ") + std::to_string(GetLastError()) + OBF(".") };

	// Read the next chunk of data up to the length specified in the previous four bytes.
	ByteVector buffer;
	buffer.resize(chunkLength);
	for (DWORD bytesReadTotal = 0; bytesReadTotal < chunkLength; bytesReadTotal += bytesReadCurrent)
		if (!ReadFile(m_Pipe.get(), &buffer[bytesReadTotal], chunkLength - bytesReadTotal, &bytesReadCurrent, nullptr))
			throw std::runtime_error{ OBF("Couldn't read from Pipe: ") + std::to_string(GetLastError()) + OBF(".") };

	return buffer;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::WinTools::AlternatingPipe::WriteCov(ByteView data)
{
	DWORD written;
	DWORD start = 0, size = static_cast<DWORD>(data.size());

	uint32_t len = static_cast<uint32_t>(data.size());
	BYTE* bytes = (BYTE*)& len;
	DWORD32 chunkLength = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];

	//Write the length first
	WriteFile(m_Pipe.get(), &chunkLength, 4, nullptr, nullptr);

	//We have to write in chunks of 1024, this is mirrored in how the Grunt reads.
	const uint8_t* d = &data.front();
	while (size > 1024)
	{
		WriteFile(m_Pipe.get(), d + start, 1024, &written, nullptr);
		start += 1024;
		size -= 1024;
	}
	WriteFile(m_Pipe.get(), d + start, size, &written, nullptr);
	start += size;

	if (start != data.size())
		throw std::runtime_error{ OBF("Write pipe failed ") };

	// Removed because double pipes don't require it and it causes a deadlock.
	// Let Read() know that the pipe is ready to be read.
	//SetEvent(m_Event.get());
	return data.size();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
size_t FSecure::WinTools::AlternatingPipe::Write(ByteView data)
{
	// Write four bytes indicating the length of the next chunk of data.
	DWORD chunkLength = static_cast<DWORD>(data.size()), bytesWritten = 0;
	if (!WriteFile(m_Pipe.get(), &chunkLength, 4, &bytesWritten, nullptr))
		throw std::runtime_error{ OBF("Couldn't write to Pipe: ") + std::to_string(GetLastError()) + OBF(".") };

	// Write the chunk.
	if (!WriteFile(m_Pipe.get(), &data.front(), chunkLength, &bytesWritten, nullptr))
		throw std::runtime_error{ OBF("Couldn't write to Pipe: ") + std::to_string(GetLastError()) + OBF(".") };

	// Let Read() know that the pipe is ready to be read.
	SetEvent(m_Event.get());

	return data.size();
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::WinTools::AsyncPipe::AsyncPipe(ByteView pipeName) : m_PipeName(OBF("\\\\.\\pipe\\") + std::string{ pipeName })
{
	// Connect to the named pipe server
	this->hPipe = CreateFileA(
		this->m_PipeName.c_str(),                       // Pipe name
		GENERIC_READ | GENERIC_WRITE,   // Desired access
		0,                              // Share mode (0 = not shared)
		NULL,                           // Security attributes
		OPEN_EXISTING,                  // Creation disposition
		FILE_FLAG_OVERLAPPED,           // Flags and attributes (overlapped I/O)
		NULL                            // Template file handle (not used for pipes)
	);

	if (this->hPipe == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to connect to named pipe. Error code: " << GetLastError() << std::endl;
		throw std::runtime_error{ OBF("Couldn't open named") };
	}

	this->alertEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
	if (alertEvent == nullptr)
	{
		std::cerr << "Failed to create alert event. Error code: " << GetLastError() << std::endl;
		// Handle the error as needed
	}

	std::cout << "Connected to named pipe server." << std::endl;
}

void FSecure::WinTools::AsyncPipe::DeserializeToReceiverQueue(FSecure::C3::Interfaces::Connectors::Messages::ChunkMessageEventArgs<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked> args)
{
	std::string fullMsg = "";
	
	// For loop to iterate the chunks
	for (int i = 0; i < args.GetMessages().size(); i++) {
		auto decoded = base64::decode<std::string>(args.GetMessages()[i].data);
		fullMsg += decoded;
	}
	if (args.GetMessages()[0].message_type == 15) {
		this->message_type = 16;
	}
	else {
		this->message_type = 19;
	}

	// TODO: Add to receiver queue
	this->messageQueue.push(fullMsg);
}

VOID CALLBACK FSecure::WinTools::AsyncPipe::ReadCompletionRoutine(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped)
{
	return;
	// TOOD: Need to get pointer to relevant instance
	AsyncPipe* instance = reinterpret_cast<AsyncPipe*>(lpOverlapped->hEvent);
	if (dwErrorCode == 0)
	{
		// Read operation completed successfully
		//char* buffer = reinterpret_cast<char*>(lpOverlapped->hEvent);
		// 
		//std::cout << "Received data: " << instance->readBuffer << std::endl;

		//instance->lastMsg = std::vector<char>(instance->readBuffer, instance->readBuffer + dwNumberOfBytesTransfered);

		std::cout << "Received data: " << instance->lastMsg.data() << std::endl;
		//instance->_senderQueue.emplace(instance->readBuffer);
		//instance->senderEvent->notify_one();
		instance->ready = true;
		instance->messageQueue.push(std::string(instance->lastMsg.begin(), instance->lastMsg.end()));
		
		// TODO: use chunk message struct to follow message completion
		json msg = json::parse(std::string("this is a commad"));
		FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked msgObj = msg.get<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>();

		if (instance->messageStore.ContainsKey(msgObj.id)) {
			std::shared_ptr<FSecure::C3::Interfaces::Connectors::Messages::ChunkedMessageStore<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>> nmsg = std::make_shared<FSecure::C3::Interfaces::Connectors::Messages::ChunkedMessageStore<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>>();
			instance->messageStore.Add(msgObj.id, nmsg);
			instance->messageStore[msgObj.id]->MessageComplete = [&instance](FSecure::C3::Interfaces::Connectors::Messages::ChunkMessageEventArgs<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked> args) {instance->DeserializeToReceiverQueue(args);};
		}
		instance->messageStore[msgObj.id]->AddMessage(msgObj);
	}
	else
	{
		// Read operation failed
		std::cerr << "Read operation failed with error code: " << dwErrorCode << std::endl;
	}
}

void FSecure::WinTools::AsyncPipe::AsyncWrite(ByteView data)
{
	auto datastring = std::string(data);

	int chunkLength = 15000;
	int totalChunks = data.length() / chunkLength + 1;
	UUID uuid;
	UuidCreate(&uuid);
	char* uuidstr;
	UuidToStringA(&uuid, (RPC_CSTR*)&uuidstr);
	std::string uuids(uuidstr);

	for (int i = 0; i < totalChunks; i++) {
		// Construct message
		FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked msg;
		msg.id = uuids;
		msg.message_type = this->message_type;
		msg.chunk_number = i + 1;
		msg.total_chunks = totalChunks;

		std::string chunk = datastring.substr(i * chunkLength, chunkLength);
		//std::string datan(resp.begin(), resp.end());
		msg.data = base64::encode(chunk);
		json msgjson = msg;
		std::string msgserialized = msgjson.dump();

		
		WriteFile(
			this->hPipe,
			msgserialized.c_str(),
			static_cast<DWORD>(msgserialized.size()),
			nullptr,
			nullptr
		);
		Sleep(1000);
	}

}

void FSecure::WinTools::AsyncPipe::AsyncRead() 
{
	std::thread readThread(&AsyncPipe::AsyncReadThread, this);
	readThread.detach();
}

void FSecure::WinTools::AsyncPipe::AsyncReadThread()
{
	try {
		// Create overlapped structure for read operation
		ZeroMemory(&this->overlappedRead, sizeof(this->overlappedRead));
		this->overlappedRead.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr); // Use the read buffer as the event handle
		this->readBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE);
		/*this->readBuffer = new char[BUFFER_SIZE];
		memset(this->readBuffer, 0, BUFFER_SIZE);*/

		while (true) {
			// TODO: Close thread and kill instance when pipe is broken
			
			//this->overlappedRead.hEvent = reinterpret_cast<HANDLE>(this); // Use the read buffer as the event handle
			
			// Perform asynchronous read operation
			BOOL isReadPending = ReadFileEx(
				this->hPipe,                          // Pipe handle
				this->readBuffer,                     // Buffer to read into
				BUFFER_SIZE,                    // Number of bytes to read
				&this->overlappedRead,                // Overlapped structure
				ReadCompletionRoutine           // Completion routine
			);

			if (!isReadPending)
			{
				std::cerr << "Failed to initiate read operation. Error code: " << GetLastError() << std::endl;
				//delete[] readBuffer;
				//CloseHandle(this->hPipe);
			}
			
			// Wait for the completion routine to be called
			DWORD result = WaitForSingleObjectEx(this->overlappedRead.hEvent, INFINITE, TRUE);
			//DWORD result = SleepEx(INFINITE, TRUE);
			std::cout << "result of wait: " << result << std::endl;
			DWORD byteRead;
			BOOL oresult = GetOverlappedResult(hPipe, &this->overlappedRead, &byteRead, FALSE);
			std::cout << "debug print " << std::endl;
			std::string rd(reinterpret_cast<char*>(this->readBuffer), byteRead);
			//this->messageQueue.push(rd);

			// TODO: Move from here
			json msg;
			try 
			{
				msg = json::parse(rd);
			}
			catch (...) { continue; }

			FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked msgObj = msg.get<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>();

			if (!this->messageStore.ContainsKey(msgObj.id)) {
				std::shared_ptr<FSecure::C3::Interfaces::Connectors::Messages::ChunkedMessageStore<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>> nmsg = std::make_shared<FSecure::C3::Interfaces::Connectors::Messages::ChunkedMessageStore<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>>();
				this->messageStore.Add(msgObj.id, nmsg);
				this->messageStore[msgObj.id]->MessageComplete = std::bind(&AsyncPipe::DeserializeToReceiverQueue, this, std::placeholders::_1);
			}
			this->messageStore[msgObj.id]->AddMessage(msgObj);
		}
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	catch (...) {
		std::cout << "Unknown exception occured" << std::endl;
	}
	// Clean up
	//delete[] readBuffer;
	//CloseHandle(this->hPipe);
}