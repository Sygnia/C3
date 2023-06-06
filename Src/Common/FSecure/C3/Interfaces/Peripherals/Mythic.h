#pragma once

#include <optional>
#include <metahost.h>

#include "Common/FSecure/WinTools/Pipe.h"

/// Forward declaration of Connector associated with implant.
/// Connectors implementation is only available on GateRelay, not NodeRelays.
/// Declaration must be identical to Connector definition. Namespace or struct/class mismatch will make Peripheral unusable.
namespace FSecure::C3::Interfaces::Connectors { class MythicServer; }

namespace FSecure::C3::Interfaces::Peripherals
{
	/// Class representing Mythic implant.
	class Mythic : public Peripheral<Mythic, Connectors::MythicServer>
	{
	public:
		/// Public Constructor.
		/// @param ByteView unused.
		Mythic(ByteView);

		/// Destructor
		virtual ~Mythic() = default;

		/// Sending callback implementation.
		/// @param packet to send to the Implant.
		void OnCommandFromConnector(ByteView packet) override;

		/// Callback that handles receiving from the Mythic.
		/// @returns ByteVector data received.
		ByteVector OnReceiveFromPeripheral() override;

		/// Return json with commands.
		/// @return Capability description in JSON format.
		static ByteView GetCapability();

		/// Processes internal (C3 API) Command.
		/// @param command a buffer containing whole command and it's parameters.
		/// @return ByteVector command result.
		ByteVector OnRunCommand(ByteView command) override;


	private:
		/// Example of internal command of peripheral. Must be described in GetCapability, and handled in OnRunCommand
		/// @param arg all arguments send to method.
		/// @returns ByteVector response for command.
		ByteVector TestErrorCommand(ByteView arg);

		std::optional<WinTools::AsyncPipe> m_Pipe;
		//std::optional<WinTools::AlternatingPipe> m_Pipe;
		//std::optional<WinTools::AlternatingPipe> m_PipeW;

		/// Used to delay receiving data from Mythic implementaion.
		std::chrono::time_point<std::chrono::steady_clock> m_NextMessageTime;
		std::queue<std::vector<uint8_t>> _senderQueue;

	};
}
