#include <sourcemod>
#include <regex>
#include <socket>
#include <websocket>
#include <base64>
#include <sha1>


#pragma semicolon 1
#pragma dynamic 65536
#pragma newdecls required

#define PLUGIN_VERSION "1.2"

#define DEBUG 0
#if DEBUG > 0
char g_sLog[PLATFORM_MAX_PATH];
#endif



/**
 * This implementation follows the draft version 17 of the websocket protocol specifications
 * http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17
 */

// Used in the g_hMasterSocketPlugins child arrays
enum MasterPluginCallbacks {
	Handle:MPC_PluginHandle,
	Function:MPC_ErrorCallback,
	Function:MPC_IncomingCallback,
	Function:MPC_CloseCallback
}

enum ChildPluginCallbacks {
	Handle:CPC_PluginHandle,
	Function:CPC_ReceiveCallback,
	Function:CPC_DisconnectCallback,
	Function:CPC_ErrorCallback,
	Function:CPC_ReadystateCallback
}

#define FRAGMENT_MAX_LENGTH 32768
#define URL_MAX_LENGTH 2000

// Handshake header parsing
Regex g_hRegExKey;
Regex g_hRegExPath;
Regex g_hRegExProtocol;

// Array of all master sockets we're listening on
ArrayList g_hMasterSockets;
ArrayList g_hMasterSocketHostPort;
ArrayList g_hMasterSocketIndexes;
// Array of arrays containing plugin handles which use this socket
ArrayList g_hMasterSocketPlugins;
ArrayList g_hMasterErrorForwards;
ArrayList g_hMasterCloseForwards;
ArrayList g_hMasterIncomingForwards;
// Array connecting g_hChildSockets with g_hMasterSockets
ArrayList g_hChildsMasterSockets;
// Array of child sockets spawned by a master socket. Child indexes are mapped to master sockets via g_hMasterChildSockets {child => master,...}
ArrayList g_hChildSockets;
// Array of arrays containing plugin handles which use this child socket
ArrayList g_hChildSocketPlugins;
ArrayList g_hChildSocketIndexes;
ArrayList g_hChildSocketHost;
ArrayList g_hChildSocketPort;
ArrayList g_hChildSocketReadyState;
ArrayList g_hChildSocketFragmentedPayload;
ArrayList g_hChildErrorForwards;
ArrayList g_hChildReceiveForwards;
ArrayList g_hChildDisconnectForwards;
ArrayList g_hChildReadyStateChangeForwards;
//new Handle:g_hChildRandomParameter;

// This is passed as "handle" to plugins
int g_iLastSocketIndex;


enum WebsocketFrameType {
	FrameType_Continuation = 0,
	FrameType_Text = 1,
	FrameType_Binary = 2,
	FrameType_Close = 8,
	FrameType_Ping = 9,
	FrameType_Pong = 10
}

enum WebsocketFrame
{
	FIN,
	RSV1,
	RSV2,
	RSV3,
	WebsocketFrameType:OPCODE,
	MASK,
	PAYLOAD_LEN,
	String:MASKINGKEY[5],
	CLOSE_REASON
}

public Plugin myinfo = 
{
	name = "Websocket",
	author = "Jannik \"Peace-Maker\" Hartung",
	description = "Websocket protocol implementation",
	version = PLUGIN_VERSION,
	url = "http://www.wcfan.de/"
}

public APLRes AskPluginLoad2(Handle myself, bool late, char[] error, int err_max)
{
	RegPluginLibrary("websocket");
	
	CreateNative("Websocket_Open", Native_Websocket_Open);
	CreateNative("Websocket_HookChild", Native_Websocket_HookChild);
	CreateNative("Websocket_HookReadyStateChange", Native_Websocket_HookReadyStateChange);
	CreateNative("Websocket_GetReadyState", Native_Websocket_GetReadyState);
	CreateNative("Websocket_Send", Native_Websocket_Send);
	CreateNative("Websocket_UnhookChild", Native_Websocket_UnhookChild);
	CreateNative("Websocket_Close", Native_Websocket_Close);
	
	CreateNative("WebSocket.WebSocket", Native_Websocket_Open);
	CreateNative("WebSocket.HookChild", Native_Websocket_HookChild);
	CreateNative("WebSocket.HookReadyStateChange", Native_Websocket_HookReadyStateChange);
	CreateNative("WebSocket.ReadyState.get", Native_Websocket_GetReadyState);
	CreateNative("WebSocket.Send", Native_Websocket_Send);
	CreateNative("WebSocket.UnhookChild", Native_Websocket_UnhookChild);
	CreateNative("WebSocket.Close", Native_Websocket_Close);
	
	
	
	return APLRes_Success;
}

public void OnPluginStart()
{
	CreateConVar("sm_websocket_version", PLUGIN_VERSION, "", FCVAR_NOTIFY|FCVAR_REPLICATED|FCVAR_DONTRECORD);
	
	/* Do we need this?
	if(hVersion != null)
		SetConVarString(hVersion, PLUGIN_VERSION);
	*/
	
	// Setup handshake http header parsing regexes
	RegexError iRegExError;
	char sError[64];
	
	g_hRegExKey = new Regex("Sec-WebSocket-Key: (.*)\r\n", 0, sError, sizeof(sError), iRegExError);
	if(g_hRegExKey == null)
	{
		SetFailState("Can't compile Sec-WebSocket-Key regex: %s (%d)", sError, view_as<int>(iRegExError));
	}
	
	g_hRegExPath = new Regex("GET (.*)( HTTP/1.\\d)\r\n", 0, sError, sizeof(sError), iRegExError);
	if(g_hRegExPath == null)
	{
		SetFailState("Can't compile GET-Path regex: %s (%d)", sError, view_as<int>(iRegExError));
	}
	
	g_hRegExProtocol = new Regex("Sec-WebSocket-Protocol: (.*)\r\n", 0, sError, sizeof(sError), iRegExError);
	if(g_hRegExProtocol == null)
	{
		SetFailState("Can't compile Sec-WebSocket-Protocol regex: %s (%d)", sError, view_as<int>(iRegExError));
	}
	
	g_hMasterSockets = new ArrayList();
	g_hMasterSocketHostPort = new ArrayList(ByteCountToCells(128));
	g_hMasterSocketIndexes = new ArrayList();
	g_hMasterSocketPlugins = new ArrayList();
	g_hChildsMasterSockets = new ArrayList();
	g_hChildSockets = new ArrayList();
	g_hChildSocketIndexes = new ArrayList();
	g_hChildSocketPlugins = new ArrayList();
	g_hChildSocketHost = new ArrayList(ByteCountToCells(64));
	g_hChildSocketPort = new ArrayList();
	g_hChildSocketReadyState = new ArrayList();
	g_hChildSocketFragmentedPayload = new ArrayList();
	
	g_hMasterErrorForwards = new ArrayList();
	g_hMasterCloseForwards = new ArrayList();
	g_hMasterIncomingForwards = new ArrayList();
	g_hChildErrorForwards = new ArrayList();
	g_hChildReceiveForwards = new ArrayList();
	g_hChildDisconnectForwards = new ArrayList();
	g_hChildReadyStateChangeForwards = new ArrayList();
	
#if DEBUG > 0
	BuildPath(Path_SM, g_sLog, sizeof(g_sLog), "logs/websocket_debug.log");
#endif
}

public void OnPluginEnd()
{
	while(g_hMasterSockets.Length)
		CloseMasterSocket(0);
}

public int Native_Websocket_Open(Handle plugin, int numParams)
{
	int iSize = g_hMasterSocketPlugins.Length;
	ArrayList hMasterSocketPlugins;
	Handle aPluginInfo[MasterPluginCallbacks];
	
	// Currently only one websocket per plugin is supported.
	int iPluginCount;
	for(int i = 0; i < iSize; i++)
	{
		hMasterSocketPlugins = g_hMasterSocketPlugins.Get(i);
		iPluginCount = hMasterSocketPlugins.Length;
		for(int p = 0; p < iPluginCount; p++)
		{
			hMasterSocketPlugins.GetArray(p, aPluginInfo[0], view_as<int>(MasterPluginCallbacks));
			if(aPluginInfo[MPC_PluginHandle] == plugin)
			{
				return ThrowNativeError(SP_ERROR_NATIVE, "Only one websocket per plugin allowed. You already got one open.");
			}
		}
	}
	
	int  iHostNameLength;
	GetNativeStringLength(1, iHostNameLength);
	if(iHostNameLength <= 0)
	{
		return 0;
	}
	
	char[] sHostName = new char[iHostNameLength+1];
	GetNativeString(1, sHostName, iHostNameLength+1);
	
	int iPort = GetNativeCell(2);
	
	int iIndex = -1;
	
	// Is there already a socket open on that hostname:port?
	char sHostPort[128];
	char sHostPortStored[128];
	
	Format(sHostPort, sizeof(sHostPort), "%s:%d", sHostName, iPort);
	iSize = g_hMasterSocketHostPort.Length;

	for(int i=0; i < iSize; i++)
	{
		g_hMasterSocketHostPort.GetString(i, sHostPortStored, sizeof(sHostPortStored));
		// Yes there is. Just add this plugin to the listeners
		if(StrEqual(sHostPort, sHostPortStored, false))
		{
			iIndex = i;
			break;
		}
	}
	
	// Only create the socket, if it's not there already!
	Handle hErrorForward;
	Handle hCloseForward;
	Handle hIncomingForward;
	Handle iPseudoHandle;
	
	if(iIndex == -1)
	{
		Handle hMasterSocket = SocketCreate(SOCKET_TCP, OnSocketError);
		
		if(SocketSetOption(hMasterSocket, SocketReuseAddr, 1) != 1)
		{
			return ThrowNativeError(SP_ERROR_NATIVE, "Can't set SO_REUSEADDR option.");
		}
		
		if(!SocketBind(hMasterSocket, sHostName, iPort))
		{
			return ThrowNativeError(SP_ERROR_NATIVE, "Unable to bind socket to %s:%d", sHostName, iPort);
		}
		
		if(!SocketListen(hMasterSocket, OnSocketIncoming))
		{
			return ThrowNativeError(SP_ERROR_NATIVE, "Unable to listen on socket to %s:%d", sHostName, iPort);
		}
		
		// Save the socket!
		iIndex = g_hMasterSockets.Push(hMasterSocket);
		Debug(1, "Created socket on %s:%d #%d", sHostName, iPort, iIndex);
		
		// this should always be in sync with g_hMasterSockets
		iPseudoHandle = view_as<Handle>(++g_iLastSocketIndex);
		g_hMasterSocketIndexes.Push(iPseudoHandle);
		
		// Create private forwards for this socket
		hIncomingForward = CreateForward(ET_Event, Param_Cell, Param_Cell, Param_String, Param_Cell, Param_String, Param_String);
		g_hMasterIncomingForwards.Push(hIncomingForward);
		
		hErrorForward = CreateForward(ET_Ignore, Param_Cell, Param_Cell, Param_Cell);
		g_hMasterErrorForwards.Push(hErrorForward);
		
		hCloseForward = CreateForward(ET_Ignore, Param_Cell);
		g_hMasterCloseForwards.Push(hCloseForward);
		
		SocketSetArg(hMasterSocket, iPseudoHandle);
		
		// Save the hostname:port combi to check, if there's already a socket open.
		// We just pass the handle to the plugin calling instead of creating a new socket.
		g_hMasterSocketHostPort.PushString(sHostPort);
	}
	// There's already a connection open. Get the details
	else
	{
		iPseudoHandle = g_hMasterSocketIndexes.Get(iIndex);
		hIncomingForward = g_hMasterIncomingForwards.Get(iIndex);
		hErrorForward = g_hMasterErrorForwards.Get(iIndex);
		hCloseForward = g_hMasterCloseForwards.Get(iIndex);
		Debug(1, "Using old socket on %s:%d #%d", sHostName, iPort, iIndex);
	}
	
	// Add him to our private incoming connections forward for this socket
	Function fIncomingCallback = GetNativeFunction(3);
	if(!AddToForward(hIncomingForward, plugin, fIncomingCallback))
		LogError("Unable to add plugin to incoming callback");
	
	// Add him to our private error forward for this socket
	Function fErrorCallback = GetNativeFunction(4);
	if(!AddToForward(hErrorForward, plugin, fErrorCallback))
		LogError("Unable to add plugin to error callback");
	
	// Add him to our private close forward for this socket
	Function fCloseCallback = GetNativeFunction(5);
	if(!AddToForward(hCloseForward, plugin, fCloseCallback))
		LogError("Unable to add plugin to close callback");
	
	// Remember, that this plugin is using this socket. Required to determine, if we can close the socket, if no plugins are using it anymore.
	if(iIndex >= iSize)
	{
		hMasterSocketPlugins = new ArrayList(view_as<int>(MasterPluginCallbacks));
		g_hMasterSocketPlugins.Push(hMasterSocketPlugins);
	}
	else
		hMasterSocketPlugins = g_hMasterSocketPlugins.Get(iIndex);
	
	aPluginInfo[MPC_PluginHandle] = plugin;
	aPluginInfo[MPC_ErrorCallback] = fErrorCallback;
	aPluginInfo[MPC_IncomingCallback] = fIncomingCallback;
	aPluginInfo[MPC_CloseCallback] = fCloseCallback;
	hMasterSocketPlugins.PushArray(aPluginInfo[0], view_as<int>(MasterPluginCallbacks));
	
	return view_as<int>(iPseudoHandle);
}

public int Native_Websocket_Send(Handle plugin, int numParams)
{
	WebSocket iPseudoChildHandle = GetNativeCell(1);
	int iChildIndex;
	if(iPseudoChildHandle == INVALID_WEBSOCKET_HANDLE
	|| (iChildIndex = g_hChildSocketIndexes.FindValue(iPseudoChildHandle)) == -1)
	{
		return ThrowNativeError(SP_ERROR_NATIVE, "Invalid child websocket handle.");
	}
	
	int vFrame[WebsocketFrame];
	vFrame[OPCODE] = GetNativeCell(2) == SendType_Text ? FrameType_Text : FrameType_Binary;
	
	vFrame[PAYLOAD_LEN] = GetNativeCell(4);
	if(vFrame[PAYLOAD_LEN] == -1)
		GetNativeStringLength(3, vFrame[PAYLOAD_LEN]);
	
	char[] sPayLoad = new char[vFrame[PAYLOAD_LEN]+1];
	
	GetNativeString(3, sPayLoad, vFrame[PAYLOAD_LEN]+1);
	
	vFrame[FIN] = 1;
	vFrame[CLOSE_REASON] = -1;
	SendWebsocketFrame(iChildIndex, sPayLoad, vFrame);
	return true;
}

public int Native_Websocket_HookChild(Handle plugin, int numParams)
{
	WebSocket iPseudoChildHandle = GetNativeCell(1);
	int iChildIndex;
	if(iPseudoChildHandle == INVALID_WEBSOCKET_HANDLE
	|| (iChildIndex = g_hChildSocketIndexes.FindValue(iPseudoChildHandle)) == -1)
	{
		return ThrowNativeError(SP_ERROR_NATIVE, "Invalid child websocket handle.");
	}
	
	Handle hReceiveForward = g_hChildReceiveForwards.Get(iChildIndex);
	Handle hErrorForward = g_hChildErrorForwards.Get(iChildIndex);
	Handle hDisconnectForward = g_hChildDisconnectForwards.Get(iChildIndex);
	
	// Did this plugin already hook the child socket? Replace callbacks!
	ArrayList hChildSocketPlugin = g_hChildSocketPlugins.Get(iChildIndex);
	int iPluginCount = hChildSocketPlugin.Length;
	int aPluginInfo[ChildPluginCallbacks];
	int iPluginInfoIndex = -1;
	for(int p = 0; p < iPluginCount; p++)
	{
		hChildSocketPlugin.GetArray(p, aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
		if(plugin == aPluginInfo[CPC_PluginHandle])
		{
			iPluginInfoIndex = p;
			// Only remove, if there are already callbacks set. This could happen, if ReadyStateChange was called before HookChild.
			if(aPluginInfo[CPC_ReceiveCallback] != INVALID_FUNCTION)
			{
				RemoveFromForward(hReceiveForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReceiveCallback]);
				RemoveFromForward(hDisconnectForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_DisconnectCallback]);
				RemoveFromForward(hErrorForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ErrorCallback]);
				break;
			}
		}
	}
	
	aPluginInfo[CPC_ReceiveCallback] = GetNativeFunction(2);
	aPluginInfo[CPC_DisconnectCallback] = GetNativeFunction(3);
	aPluginInfo[CPC_ErrorCallback] = GetNativeFunction(4);
	
	// This is the first call to a hooking function on this socket for this plugin.
	if(iPluginInfoIndex == -1)
	{
		// Store this plugin's callbacks to be able to remove them from the forward by the time the child socket disconnects
		aPluginInfo[CPC_PluginHandle] = plugin;
		aPluginInfo[CPC_ReadystateCallback] = INVALID_FUNCTION;
		
		hChildSocketPlugin.PushArray(aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
	// This plugin is already known.
	} else {
		hChildSocketPlugin.SetArray(iPluginInfoIndex, aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
	}
	
	// Add his callbacks to the private forwards
	if(!AddToForward(hReceiveForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReceiveCallback]))
		LogError("Unable to add plugin to recv callback");
	if(!AddToForward(hDisconnectForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_DisconnectCallback]))
		LogError("Unable to add plugin to disc callback");
	if(!AddToForward(hErrorForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ErrorCallback]))
		LogError("Unable to add plugin to err callback");
	
	return true;
}

// Return the ready state of a child socket
public int Native_Websocket_HookReadyStateChange(Handle plugin, int numParams)
{
	WebSocket iPseudoChildHandle = GetNativeCell(1);
	int iChildIndex;
	if(iPseudoChildHandle == INVALID_WEBSOCKET_HANDLE
	|| (iChildIndex = g_hChildSocketIndexes.FindValue(iPseudoChildHandle)) == -1)
	{
		return ThrowNativeError(SP_ERROR_NATIVE, "Invalid child websocket handle.");
	}
	
	Handle hReadyStateChangeForward = g_hChildReadyStateChangeForwards.Get(iChildIndex);
	
	// Check, if this plugin already hooked this socket.
	ArrayList hChildSocketPlugin = g_hChildSocketPlugins.Get(iChildIndex);
	int iPluginCount = hChildSocketPlugin.Length;
	int aPluginInfo[ChildPluginCallbacks];
	int iPluginInfoIndex = -1;
	
	for(int p = 0; p < iPluginCount; p++)
	{
		hChildSocketPlugin.GetArray(p, aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
		if(plugin == aPluginInfo[CPC_PluginHandle])
		{
			iPluginInfoIndex = p;
			// Replace the callback, if we already stored one.
			if(aPluginInfo[CPC_ReadystateCallback] != INVALID_FUNCTION)
			{
				RemoveFromForward(hReadyStateChangeForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReadystateCallback]);
				break;
			}
		}
	}
	
	// Save the function to call.
	aPluginInfo[CPC_ReadystateCallback] = GetNativeFunction(2);
	
	// This is the first call for a plugin to call a hooking function.
	if(iPluginInfoIndex == -1)
	{
		aPluginInfo[CPC_PluginHandle] = plugin;
		aPluginInfo[CPC_ReceiveCallback] = INVALID_FUNCTION;
		aPluginInfo[CPC_ErrorCallback] = INVALID_FUNCTION;
		aPluginInfo[CPC_DisconnectCallback] = INVALID_FUNCTION;
		
		hChildSocketPlugin.PushArray(aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
	}
	else
	{
		hChildSocketPlugin.SetArray(iPluginInfoIndex, aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
	}
	
	if(!AddToForward(hReadyStateChangeForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReadystateCallback]))
		LogError("Unable to add plugin to readystate change callback");
	
	return true;
}

// Return the ready state of a child socket
public int Native_Websocket_GetReadyState(Handle plugin, int numParams)
{
	WebSocket iPseudoChildHandle = GetNativeCell(1);
	int iChildIndex;
	if(iPseudoChildHandle == INVALID_WEBSOCKET_HANDLE
	|| (iChildIndex = g_hChildSocketIndexes.FindValue(iPseudoChildHandle)) == -1)
	{
		return ThrowNativeError(SP_ERROR_NATIVE, "Invalid child websocket handle.");
	}
	
	return g_hChildSocketReadyState.Get(iChildIndex);
}

public int Native_Websocket_UnhookChild(Handle plugin, int numParams)
{
	WebSocket iPseudoChildHandle = GetNativeCell(1);
	int iChildIndex;
	if(iPseudoChildHandle == INVALID_WEBSOCKET_HANDLE
	|| (iChildIndex = g_hChildSocketIndexes.FindValue(iPseudoChildHandle)) == -1)
	{
		return ThrowNativeError(SP_ERROR_NATIVE, "Invalid child websocket handle.");
	}
	
	Handle hReceiveForward = g_hChildReceiveForwards.Get(iChildIndex);
	Handle hDisconnectForward = g_hChildDisconnectForwards.Get(iChildIndex);
	Handle hErrorForward = g_hChildErrorForwards.Get(iChildIndex);
	Handle hReadyStateChangeForward = g_hChildReadyStateChangeForwards.Get(iChildIndex);
	
	ArrayList hChildSocketPlugin = g_hChildSocketPlugins.Get(iChildIndex);
	int iPluginCount = hChildSocketPlugin.Length;
	int aPluginInfo[ChildPluginCallbacks];
	for(int p = 0; p < iPluginCount; p++)
	{
		hChildSocketPlugin.GetArray(p, aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
		if(aPluginInfo[CPC_PluginHandle] == plugin)
		{
			// Remove the caller from all forwards
			if(aPluginInfo[CPC_ReceiveCallback] != INVALID_FUNCTION)
			{
				RemoveFromForward(hReceiveForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReceiveCallback]);
				RemoveFromForward(hDisconnectForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_DisconnectCallback]);
				RemoveFromForward(hErrorForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ErrorCallback]);
			}
			// Did this plugin call Websocket_HookReadyStateChange?
			if(aPluginInfo[CPC_ReadystateCallback] != INVALID_FUNCTION)
				RemoveFromForward(hReadyStateChangeForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReadystateCallback]);
			hChildSocketPlugin.Erase(p);
			break;
		}
	}
	
	// No plugin is using this anymore. Close the connection.
	if(hChildSocketPlugin.Length == 0)
		CloseConnection(iChildIndex, 1000, "");
		
	return 1;
}

public int Native_Websocket_Close(Handle plugin, int numParams)
{
	WebSocket iPseudoHandle = GetNativeCell(1);
	int iIndex;
	if(iPseudoHandle == INVALID_WEBSOCKET_HANDLE
	|| (iIndex = g_hMasterSocketIndexes.FindValue(iPseudoHandle)) == -1)
	{
		return ThrowNativeError(SP_ERROR_NATIVE, "Invalid websocket handle.");
	}
	
	CloseMasterSocket(iIndex);
	return 1;
}

public int OnSocketError(Handle socket, const int errorType, const int errorNum, any arg)
{
	int iIndex = g_hMasterSocketIndexes.FindValue(arg);
	// That should never happen :/
	if(iIndex != -1)
	{
		CloseMasterSocket(iIndex, true, errorType, errorNum);
	}
	else
		socket.Close();
}

void CloseMasterSocket(int iIndex, bool bError = false, int errorType = -1, int errorNum = -1)
{
	int iPseudoHandle = g_hMasterSocketIndexes.Get(iIndex);
	Handle hErrorForward = g_hMasterErrorForwards.Get(iIndex);
	Handle hIncomingForward = g_hMasterIncomingForwards.Get(iIndex);
	Handle hCloseForward = g_hMasterCloseForwards.Get(iIndex);
	
	// Close all child sockets first.
	int iChildSockets = g_hChildsMasterSockets.Length;
	for(int i = 0; i < iChildSockets; i++)
	{
		if(g_hChildsMasterSockets.Get(i) == iIndex)
			CloseConnection(i, 1001, "");
	}
	
	// Only bother notifying other plugins, if there are still any listening at all.
	if(GetForwardFunctionCount(hIncomingForward) > 0)
	{
		// There's been an error.
		if(bError)
		{
			// Inform plugins there's been an error
			Call_StartForward(hErrorForward);
			Call_PushCell(iPseudoHandle);
			Call_PushCell(errorType);
			Call_PushCell(errorNum);
			Call_PushCell(0); // Dummy value as the master socket doesn't use the any:data paramter.
			Call_Finish();
		}
		else
		{
			Call_StartForward(hCloseForward);
			Call_PushCell(iPseudoHandle);
			Call_Finish();
		}
		
		// Loop through all plugins using this socket
		ArrayList hPlugins = g_hMasterSocketPlugins.Get(iIndex);
		int iPluginCount = hPlugins.Length;
		int aPluginInfo[MasterPluginCallbacks];
		// This master socket is gone, remove forward
		for(int p = 0; p < iPluginCount; p++)
		{
			hPlugins.GetArray(p, aPluginInfo[0], view_as<int>(MasterPluginCallbacks));
			
			if(!IsPluginStillLoaded(aPluginInfo[MPC_PluginHandle]))
				continue;
			
			// Remove it from forwards.
			RemoveFromForward(hErrorForward, aPluginInfo[MPC_PluginHandle], aPluginInfo[MPC_ErrorCallback]);
			RemoveFromForward(hIncomingForward, aPluginInfo[MPC_PluginHandle], aPluginInfo[MPC_IncomingCallback]);
			RemoveFromForward(hCloseForward, aPluginInfo[MPC_PluginHandle], aPluginInfo[MPC_CloseCallback]);
		}
		hPlugins.Close();
	}
	
	g_hMasterSocketPlugins.Erase(iIndex);
	hErrorForward.Close();
	hIncomingForward.Close();
	hCloseForward.Close();
	g_hMasterErrorForwards.Erase(iIndex);
	g_hMasterIncomingForwards.Erase(iIndex);
	g_hMasterCloseForwards.Erase(iIndex);
	g_hMasterSocketHostPort.Erase(iIndex);
	
	// Close the actual master socket
	(view_as<Handle>(g_hMasterSockets.Get(iIndex))).Close();
	
	g_hMasterSockets.Erase(iIndex);
	g_hMasterSocketIndexes.Erase(iIndex);
}

public int OnSocketIncoming(Handle socket, Handle newSocket, const char[] remoteIP, int remotePort, any arg)
{
	int iIndex = g_hMasterSocketIndexes.FindValue(arg);
	// This isn't handled by anything?! GO AWAY!!1
	if(iIndex == -1)
	{
		newSocket.Close();
		return;
	}
	
	// Hook this child socket. Let the magic begin!
	SocketSetReceiveCallback(newSocket, OnChildSocketReceive);
	SocketSetDisconnectCallback(newSocket, OnChildSocketDisconnect);
	SocketSetErrorCallback(newSocket, OnChildSocketError);
	
	int iPseudoChildHandle = ++g_iLastSocketIndex;
	Handle hIncomingForward = g_hMasterIncomingForwards.Get(iIndex);
	
	// There are no plugins listening anymore?! They didn't call WebSocket_Close in OnPluginEnd.
	if(!GetForwardFunctionCount(hIncomingForward))
	{
		newSocket.Close();
		CloseMasterSocket(iIndex);
		return;
	}
	
	SocketSetArg(newSocket, iPseudoChildHandle);
	
	// Save this connection in our arrays
	g_hChildSockets.Push(newSocket);
	// Make sure we remember the master socket!
	g_hChildsMasterSockets.Push(iIndex);
	g_hChildSocketIndexes.Push(iPseudoChildHandle);
	g_hChildSocketHost.PushString(remoteIP);
	g_hChildSocketPort.Push(remotePort);
	g_hChildSocketPlugins.Push(new ArrayList(view_as<int>(ChildPluginCallbacks)));
	g_hChildSocketReadyState.Push(State_Connecting);
	ArrayList hFragmentedPayload = new ArrayList(ByteCountToCells(FRAGMENT_MAX_LENGTH));
	g_hChildSocketFragmentedPayload.Push(hFragmentedPayload);
	hFragmentedPayload.Push( 0); // The first element will always be the payload length.
	hFragmentedPayload.Push(0); // The second element is the payload type. (Even though we don't handle text and binary differently..)
	
	// Create the private forwards for this socket
	Handle hReceiveForward = CreateForward(ET_Ignore, Param_Cell, Param_Cell, Param_String, Param_Cell, Param_Any);
	g_hChildReceiveForwards.Push(hReceiveForward);
	
	Handle hErrorForward = CreateForward(ET_Ignore, Param_Cell, Param_Cell, Param_Cell, Param_Any);
	g_hChildErrorForwards.Push(hErrorForward);
	
	Handle hDisconnectForward = CreateForward(ET_Ignore, Param_Cell, Param_Any);
	g_hChildDisconnectForwards.Push(hDisconnectForward);
	
	Handle hReadyStateChangeForward = CreateForward(ET_Ignore, Param_Cell, Param_Cell, Param_Any);
	g_hChildReadyStateChangeForwards.Push(hReadyStateChangeForward);
	
	// TODO start a timouttimer which closes the connection, if no valid http upgrade request is received in time.
}

public int OnChildSocketError(Handle socket, const int errorType, const int errorNum, any arg)
{
	int iIndex = g_hChildSocketIndexes.FindValue(arg);
	// This isn't handled by anything?! GO AWAY!!1
	if(iIndex == -1)
	{
		socket.Close();
		return;
	}
	
	Handle hErrorForward = g_hChildErrorForwards.Get(iIndex);
	
	Call_StartForward(hErrorForward);
	Call_PushCell(GetArrayCell(g_hChildSocketIndexes, iIndex));
	Call_PushCell(errorType);
	Call_PushCell(errorNum);
	Call_Finish();
	
	CloseChildSocket(iIndex, false);
}

public int OnChildSocketDisconnect(Handle socket, any arg)
{
	Debug(1, "Child socket disconnected");
	int iIndex = g_hChildSocketIndexes.FindValue(arg);
	// This isn't handled by anything?! GO AWAY!!1
	if(iIndex == -1)
	{
		socket.Close();
		return;
	}
	CloseChildSocket(iIndex);
}

public int OnChildSocketReceive(Handle socket, const char[] receiveData, const int dataSize, any arg)
{
	Debug(2, "Child socket receives data: %s", receiveData);
	
	int iIndex = g_hChildSocketIndexes.FindValue(arg);
	// This isn't handled by anything?! GO AWAY!!1
	if(iIndex == -1)
	{
		socket.Close();
		return;
	}
	
	WebsocketReadyState iReadyState = g_hChildSocketReadyState.Get(iIndex);
	switch(iReadyState)
	{
		// We received the http upgrade request
		// Send the correct response to complete the handshake!
		case State_Connecting:
		{
			RegexError iRegexError;
			// Get the key
			
			int iSubStrings = g_hRegExKey.Match(receiveData, iRegexError);
			if(iSubStrings == -1)
			{
				LogError("Can't find the Key in the http protocol upgrade request.");
				CloseChildSocket(iIndex);
				return;
			}
			
			char sKey[256];
			if(!g_hRegExKey.GetSubString(1, sKey, sizeof(sKey)))
			{
				LogError("Failed to extract security key.");
				CloseChildSocket(iIndex);
				return;
			}
			
			Debug(2, "Key: %s", sKey);
			
			char sSHA1Hash[21];
			char sResponseKey[41];
			Format(sKey, sizeof(sKey), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", sKey);
			SHA1String(sKey, sSHA1Hash, false);
			EncodeBase64(sResponseKey, sizeof(sResponseKey), sSHA1Hash, 20);
			
			Debug(2, "ResponseKey: %s", sResponseKey);
			
			iSubStrings = g_hRegExProtocol.Match(receiveData, iRegexError);
			char sProtocol[256];
			if(iSubStrings != -1)
			{
				if(strlen(sProtocol) < 1 || !g_hRegExProtocol.GetSubString(0, sProtocol, sizeof(sProtocol)))
				{
					Format(sProtocol, sizeof(sProtocol), "");
					// It's not required to specify a subprotocol!
					/*LogError("Failed to extract sub protocols.");
					CloseChildSocket(iIndex);
					return;*/
				}
			}
			
			char sPath[URL_MAX_LENGTH];
			
			// Get the key
			iSubStrings = g_hRegExPath.Match(receiveData, iRegexError);
			if(iSubStrings == -1 || !g_hRegExPath.GetSubString(1, sPath, sizeof(sPath)))
				sPath = "";
			
			// Inform plugins, there's an incoming request 
			int iMasterIndex = g_hChildsMasterSockets.Get(iIndex);
			
			Handle hIncomingForward = g_hMasterIncomingForwards.Get(iMasterIndex);
			Call_StartForward(hIncomingForward);
			Call_PushCell(g_hMasterSocketIndexes.Get(iMasterIndex));
			Call_PushCell(g_hChildSocketIndexes.Get(iIndex));
			char remoteIP[65];
			g_hChildSocketHost.GetString(iIndex, remoteIP, sizeof(remoteIP));
			Call_PushString(remoteIP);
			Call_PushCell(GetArrayCell(g_hChildSocketPort, iIndex));
			// TODO SM_PARAM_STRING_UTF8 might be wrong here? SM_PARAM_STRING_COPY?
			char sProtocolReturn[256];
			strcopy(sProtocolReturn, sizeof(sProtocolReturn), sProtocol);
			Call_PushStringEx(sProtocolReturn, sizeof(sProtocolReturn), SM_PARAM_STRING_UTF8, SM_PARAM_COPYBACK);
			Call_PushString(sPath);
			
			Action iResult;
			Call_Finish(iResult);
			
			// TODO be more friendly in refusing connections by sending a proper http header.
			// Someone doesn't like this connection..
			if(iResult >= Plugin_Handled)
			{
				Debug(1, "IncomingForward is >= Plugin_Handled. Closing child socket.");
				// Uhm.. Just because of that one? plugin denying the connection, we need to revert any Websocket_HookChild call..
				CloseChildSocket(iIndex);
				
				return;
			}
			
			// Check if any plugin called Websocket_HookChild and close the socket, if not.
			ArrayList hChildSocketPlugins = g_hChildSocketPlugins.Get(iIndex);
			if(hChildSocketPlugins.Length == 0)
			{
				Debug(1, "No plugin hooked the new child socket. Closing child socket.");
				CloseChildSocket(iIndex);
				
				return;
			}
			
			// Make sure the server offered this protocol the plugin chose.
			// Should probably error out here?
			if(StrContains(sProtocol, sProtocolReturn) == -1)
			{
				Debug(1, "Plugin chose non-existant subprotocol. Offered: \"%s\" - Chosen: \"%s\"", sProtocol, sProtocolReturn);
				Format(sProtocolReturn, sizeof(sProtocolReturn), "");
			}
			else if(strlen(sProtocol) > 0)
				Format(sProtocolReturn, sizeof(sProtocolReturn), "\r\nSec-Websocket-Protocol: %s", sProtocol);
			
			// Prepare HTTP request
			char sHTTPRequest[512];
			Format(sHTTPRequest, sizeof(sHTTPRequest), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s%s\r\n\r\n", sResponseKey, sProtocolReturn);
			SocketSend(socket, sHTTPRequest);
			
			Debug(2, "Responding: %s", sHTTPRequest);
			
			g_hChildSocketReadyState.Set(iIndex, State_Open);
			
			// Inform the other plugins of the change.
			Handle hReadyStateChangeForward = g_hChildReadyStateChangeForwards.Get(iIndex);
			
			Call_StartForward(hReadyStateChangeForward);
			Call_PushCell(g_hChildSocketIndexes.Get(iIndex));
			Call_PushCell(g_hChildSocketReadyState.Get(iIndex));
			Call_Finish();
		}
		// We're open to receive info! Parse the input.
		case State_Open:
		{
			int vFrame[WebsocketFrame];
			char[] sPayLoad = new char[dataSize-1];
			ParseFrame(vFrame, receiveData, dataSize, sPayLoad);
			if(!PreprocessFrame(iIndex, vFrame, sPayLoad))
			{
				// Call forward
				//SendWebsocketFrame(iIndex, sPayLoad, vFrame);
				Handle hReceiveForward = g_hChildReceiveForwards.Get(iIndex);
				Call_StartForward(hReceiveForward);
				Call_PushCell(arg);
				
				// This is a fragmented message.
				if(vFrame[OPCODE] == FrameType_Continuation)
				{
					ArrayList hFragmentedPayload = g_hChildSocketFragmentedPayload.Get(iIndex);
					int iPayloadLength = hFragmentedPayload.Get(0);
					
					char[] sConcatPayload = new char[iPayloadLength];
					char sPayloadPart[FRAGMENT_MAX_LENGTH];
					int iSize = hFragmentedPayload.Length;
					// Concat all the payload parts
					// TODO: Make this binary safe? GetArrayArray vs. GetArrayString?
					for(int i = 2; i < iSize; i++)
					{
						hFragmentedPayload.GetString(i, sPayloadPart, sizeof(sPayloadPart));
						Format(sConcatPayload, iPayloadLength, "%s%s", sConcatPayload, sPayloadPart);
					}
					
					WebsocketSendType iType;
					if(hFragmentedPayload.Get(1) == FrameType_Text)
						iType = SendType_Text;
					else
						iType = SendType_Binary;
						
					Call_PushCell(iType);
					
					Call_PushString(sConcatPayload);
					Call_PushCell(iPayloadLength);
					
					// Clear the fragment buffer
					hFragmentedPayload.Clear();
					hFragmentedPayload.Push(0); // length
					hFragmentedPayload.Push(0); // opcode
				}
				// This is an unfragmented message.
				else
				{
					WebsocketSendType iType;
					if(vFrame[OPCODE] == FrameType_Text)
						iType = SendType_Text;
					else
						iType = SendType_Binary;
						
					Call_PushCell(iType);
					Call_PushString(sPayLoad);
					Call_PushCell(vFrame[PAYLOAD_LEN]);
				}
				
				Call_Finish();
			}
		}
	}
}

// Closes a child socket and cleans up the arrays
void CloseChildSocket(int iChildIndex, bool bFireForward = true)
{
	Debug(1, "Closing child socket #%d", iChildIndex);
	Handle hReceiveForward = g_hChildReceiveForwards.Get(iChildIndex);
	Handle hDisconnectForward = g_hChildDisconnectForwards.Get(iChildIndex);
	Handle hErrorForward = g_hChildErrorForwards.Get(iChildIndex);
	Handle hReadyStateChangeForward = g_hChildReadyStateChangeForwards.Get(iChildIndex);
	
	if(bFireForward)
	{
		Call_StartForward(hDisconnectForward);
		Call_PushCell(GetArrayCell(g_hChildSocketIndexes, iChildIndex));
		Call_Finish();
	}
	
	Handle hChildSocket = g_hChildSockets.Get(iChildIndex);
	
	g_hChildSockets.Erase(iChildIndex);
	g_hChildsMasterSockets.Erase(iChildIndex);
	g_hChildSocketHost.Erase(iChildIndex);
	g_hChildSocketPort.Erase(iChildIndex);
	g_hChildSocketReadyState.Erase(iChildIndex);

	ArrayList hChildSocketPlugin = g_hChildSocketPlugins.Get(iChildIndex);
	int iPluginCount = hChildSocketPlugin.Length;
	int aPluginInfo[ChildPluginCallbacks];
	for(int p = 0; p < iPluginCount; p++)
	{
		hChildSocketPlugin.GetArray(p, aPluginInfo[0], view_as<int>(ChildPluginCallbacks));
		if(!IsPluginStillLoaded(aPluginInfo[CPC_PluginHandle]))
			continue;
		if(aPluginInfo[CPC_ReceiveCallback] != INVALID_FUNCTION)
		{
			RemoveFromForward(hReceiveForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReceiveCallback]);
			RemoveFromForward(hDisconnectForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_DisconnectCallback]);
			RemoveFromForward(hErrorForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ErrorCallback]);
		}
		if(aPluginInfo[CPC_ReadystateCallback] != INVALID_FUNCTION)
		{
			RemoveFromForward(hReadyStateChangeForward, aPluginInfo[CPC_PluginHandle], aPluginInfo[CPC_ReadystateCallback]);
		}
	}
	CloseHandle(hChildSocketPlugin);
	g_hChildSocketPlugins.Erase(iChildIndex);
	g_hChildSocketIndexes.Erase(iChildIndex);
	(view_as<Handle>(g_hChildSocketFragmentedPayload.Get(iChildIndex))).Close();
	g_hChildSocketFragmentedPayload.Erase(iChildIndex);
	
	hReceiveForward.Close();
	hDisconnectForward.Close();
	hErrorForward.Close();
	hReadyStateChangeForward.Close();
	
	RemoveFromArray(g_hChildReceiveForwards, iChildIndex);
	RemoveFromArray(g_hChildErrorForwards, iChildIndex);
	RemoveFromArray(g_hChildDisconnectForwards, iChildIndex);
	RemoveFromArray(g_hChildReadyStateChangeForwards, iChildIndex);
	
	hChildSocket.Close();
}

void ParseFrame(int vFrame[WebsocketFrame], const char[] receiveDataLong, const int dataSize, char[] sPayLoad)
{
	// We're only interested in the first 8 bits.. what's that rest?!
	int[] receiveData = new int[dataSize];
	for(int i = 0; i < dataSize; i++)
	{
		receiveData[i] = receiveDataLong[i]&0xff;
		Debug(3, "%d (%c): %08b", i, (receiveData[i]<32?' ':receiveData[i]), receiveData[i]);
	}
	
	char sByte[9];
	Format(sByte, sizeof(sByte), "%08b", receiveData[0]);
	Debug(3, "First byte: %s", sByte);
	vFrame[FIN] = sByte[0]=='1'?1:0;
	vFrame[RSV1] = sByte[1]=='1'?1:0;
	vFrame[RSV2] = sByte[2]=='1'?1:0;
	vFrame[RSV3] = sByte[3]=='1'?1:0;
	vFrame[OPCODE] = view_as<WebsocketFrameType>(bindec(sByte[4]));
	
	Format(sByte, sizeof(sByte), "%08b", receiveData[1]);
	Debug(3, "Second byte: %s", sByte);
	vFrame[MASK] = sByte[0]=='1'?1:0;
	vFrame[PAYLOAD_LEN] = bindec(sByte[1]);
	
	int iOffset = 2;
	
	vFrame[MASKINGKEY][0] = '\0';
	if(vFrame[PAYLOAD_LEN] > 126)
	{
		char sLoongLength[49];
		for(int i = 2; i < 8; i++)
			Format(sLoongLength, sizeof(sLoongLength), "%s%08b", sLoongLength, receiveData[i]);
		
		vFrame[PAYLOAD_LEN] = bindec(sLoongLength);
		iOffset += 6;
	}
	else if(vFrame[PAYLOAD_LEN] > 125)
	{
		char sLongLength[17];
		for(int i = 2; i < 4; i++)
			Format(sLongLength, sizeof(sLongLength), "%s%08b", sLongLength, receiveData[i]);
		
		vFrame[PAYLOAD_LEN] = bindec(sLongLength);
		iOffset += 2;
	}
	if(vFrame[MASK])
	{
		for(int i = iOffset, j = 0; j < 4; i++, j++)
			vFrame[MASKINGKEY][j] = receiveData[i];
		vFrame[MASKINGKEY][4] = '\0';
		iOffset += 4;
	}
	
	int[] iPayLoad = new int[vFrame[PAYLOAD_LEN]];
	for(int i = iOffset, j = 0; j < vFrame[PAYLOAD_LEN]; i++, j++)
		iPayLoad[j] = receiveData[i];
	
	Debug(2, "dataSize: %d", dataSize);
	Debug(2, "FIN: %d", vFrame[FIN]);
	Debug(2, "RSV1: %d", vFrame[RSV1]);
	Debug(2, "RSV2: %d", vFrame[RSV2]);
	Debug(2, "RSV3: %d", vFrame[RSV3]);
	Debug(2, "OPCODE: %d", view_as<int>(vFrame[OPCODE]));
	Debug(2, "MASK: %d", vFrame[MASK]);
	Debug(2, "PAYLOAD_LEN: %d", vFrame[PAYLOAD_LEN]);
	
	// Unmask
	if(vFrame[MASK])
	{
		for(int i = 0; i < vFrame[PAYLOAD_LEN]; i++)
		{
			Format(sPayLoad, vFrame[PAYLOAD_LEN]+1, "%s%c", sPayLoad, iPayLoad[i]^vFrame[MASKINGKEY][i%4]);
		}
	}
	
	// Client requested connection close
	if(vFrame[OPCODE] == FrameType_Close)
	{
		// first 2 bytes are close reason
		char sCloseReason[65];
		for(int i = 0; i < 2; i++)
			Format(sCloseReason, sizeof(sCloseReason), "%s%08b", sCloseReason, sPayLoad[i]&0xff);
		
		vFrame[CLOSE_REASON] = bindec(sCloseReason);
		
		strcopy(sPayLoad, dataSize-1, sPayLoad[2]);
		vFrame[PAYLOAD_LEN] -= 2;
		
		Debug(2, "CLOSE_REASON: %d", vFrame[CLOSE_REASON]);
	}
	else
	{
		vFrame[CLOSE_REASON] = -1;
	}
	
	Debug(2, "PAYLOAD: %s", sPayLoad);
	
	// TODO: utf8_decode
}

bool PreprocessFrame(int iIndex, int vFrame[WebsocketFrame], char[] sPayLoad)
{
	// This is a fragmented frame
	if(vFrame[FIN] == 0)
	{
		// This is a control frame. Those cannot be fragmented!
		if(vFrame[OPCODE] >= FrameType_Close)
		{
			LogError("Received fragmented control frame. %d", vFrame[OPCODE]);
			CloseConnection(iIndex, 1002, "Received fragmented control frame.");
			return true;
		}
		
		ArrayList hFragmentedPayload = g_hChildSocketFragmentedPayload.Get(iIndex);
		int iPayloadLength = hFragmentedPayload.Get(0);
		
		// This is the first frame of a serie of fragmented ones.
		if(iPayloadLength == 0)
		{
			if(vFrame[OPCODE] == FrameType_Continuation)
			{
				LogError("Received first fragmented frame with opcode 0. The first fragment MUST have a different opcode set.");
				CloseConnection(iIndex, 1002, "Received first fragmented frame with opcode 0. The first fragment MUST have a different opcode set.");
				return true;
			}
			
			// Remember which type of message this fragmented one is.
			hFragmentedPayload.Set(1, vFrame[OPCODE]);
		}
		else
		{
			if(vFrame[OPCODE] != FrameType_Continuation)
			{
				LogError("Received second or later frame of fragmented message with opcode %d. opcode must be 0.", vFrame[OPCODE]);
				CloseConnection(iIndex, 1002, "Received second or later frame of fragmented message with opcode other than 0. opcode must be 0.");
				return true;
			}
		}
		
		// Keep track of the overall payload length of the fragmented message.
		// This is used to create the buffer of the right size when passing it to the listening plugin.
		iPayloadLength += vFrame[PAYLOAD_LEN];
		hFragmentedPayload.Set(0, iPayloadLength);
		
		// This doesn't fit inside one array cell? Split it up.
		if(vFrame[PAYLOAD_LEN] > FRAGMENT_MAX_LENGTH)
		{
			for(int i = 0; i < vFrame[PAYLOAD_LEN]; i += FRAGMENT_MAX_LENGTH)
			{
				hFragmentedPayload.PushString(sPayLoad[i]);
			}
		}
		else
		{
			hFragmentedPayload.PushString(sPayLoad);
		}
		
		return true;
	}
	
	/*if(vFrame[RSV1] != 0 || vFrame[RSV2] != 0 || vFrame[RSV3] != 0)
	{
		LogError("One of the reservation bits is set. We don't support any extensions! (rsv1: %d rsv2: %d rsv3: %d)", vFrame[RSV1], vFrame[RSV2], vFrame[RSV3]);
		CloseConnection(iIndex, 1003, "One of the reservation bits is set.");
		return false;
	}*/
	
	// The FIN bit is set if we reach here.
	switch(vFrame[OPCODE])
	{
		case FrameType_Continuation:
		{
			ArrayList hFragmentedPayload = g_hChildSocketFragmentedPayload.Get(iIndex);
			int iPayloadLength = hFragmentedPayload.Get(0);
			WebsocketFrameType iOpcode = hFragmentedPayload.Get(1);
			// We don't know what type of data that is.
			if(iOpcode == FrameType_Continuation)
			{
				LogError("Received last frame of a series of fragmented ones without any fragments with payload first.");
				CloseConnection(iIndex, 1002, "Received last frame of fragmented message without any fragments beforehand.");
				return true;
			}
			
			// Add the payload of the last frame to the buffer too.
			
			// Keep track of the overall payload length of the fragmented message.
			// This is used to create the buffer of the right size when passing it to the listening plugin.
			iPayloadLength += vFrame[PAYLOAD_LEN];
			hFragmentedPayload.Set(0, iPayloadLength);
			
			// This doesn't fit inside one array cell? Split it up.
			if(vFrame[PAYLOAD_LEN] > FRAGMENT_MAX_LENGTH)
			{
				for(int i = 0; i < vFrame[PAYLOAD_LEN]; i += FRAGMENT_MAX_LENGTH)
				{
					hFragmentedPayload.PushString(sPayLoad[i]);
				}
			}
			else
			{
				hFragmentedPayload.PushString(sPayLoad);
			}
			
			return false;
		}
		case FrameType_Text:
		{
			return false;
		}
		case FrameType_Binary:
		{
			return false;
		}
		case FrameType_Close:
		{
			// We're done here.
			if(g_hChildSocketReadyState.Get(iIndex) == State_Closing)
			{
				CloseChildSocket(iIndex);
				return true;
			}
			
			// Just mirror it back
			SendWebsocketFrame(iIndex, sPayLoad, vFrame);
			g_hChildSocketReadyState.Set(iIndex, State_Closing);
			
			Handle hReadyStateChangeForward = g_hChildReadyStateChangeForwards.Get(iIndex);
			
			// Inform the other plugins of the change.
			Call_StartForward(hReadyStateChangeForward);
			Call_PushCell(g_hChildSocketIndexes.Get(iIndex));
			Call_PushCell(GetArrayCell(g_hChildSocketReadyState, iIndex));
			Call_Finish();
			
			CloseChildSocket(iIndex);
			return true;
		}
		case FrameType_Ping:
		{
			vFrame[OPCODE] = FrameType_Pong;
			SendWebsocketFrame(iIndex, sPayLoad, vFrame);
			return true;
		}
		case FrameType_Pong:
		{
			return true;
		}
	}
	
	// This is an unknown OPCODE?! OMG
	LogError("Received invalid opcode = %d", view_as<int>(vFrame[OPCODE]));
	CloseConnection(iIndex, 1002, "Invalid opcode");
	return true;
}

bool SendWebsocketFrame(int iIndex, char[] sPayLoad, int vFrame[WebsocketFrame])
{
	WebsocketReadyState iReadyState = g_hChildSocketReadyState.Get(iIndex);
	if(iReadyState != State_Open)
	{
		return false;
	}
	
	int length = vFrame[PAYLOAD_LEN];
	
	Debug(1, "Preparing to send payload %s (%d)", sPayLoad, length);
	
	// Force RSV bits to 0
	vFrame[RSV1] = 0;
	vFrame[RSV2] = 0;
	vFrame[RSV3] = 0;
	
	char[] sFrame = new char[length+14];
	if(PackFrame(sPayLoad, sFrame, vFrame))
	{
		if(length > 65535)
			length += 10;
		else if(length > 125)
			length += 4;
		else
			length += 2;
		if(vFrame[CLOSE_REASON] != -1)
			length += 2;
		
		Debug(1, "Sending: \"%s\"", sFrame);
		Debug(2, "FIN: %d", vFrame[FIN]);
		Debug(2, "RSV1: %d", vFrame[RSV1]);
		Debug(2, "RSV2: %d", vFrame[RSV2]);
		Debug(2, "RSV3: %d", vFrame[RSV3]);
		Debug(2, "OPCODE: %d",view_as<int>(vFrame[OPCODE]));
		Debug(2, "MASK: %d", vFrame[MASK]);
		Debug(2, "PAYLOAD_LEN: %d", vFrame[PAYLOAD_LEN]);
		Debug(2, "PAYLOAD: %s", sPayLoad);
		Debug(2, "CLOSE_REASON: %d", vFrame[CLOSE_REASON]);
		Debug(2, "Frame: %s", sFrame);
		SocketSend(g_hChildSockets.Get(iIndex), sFrame, length);
		return true;
	}
	
	return false;
}

bool PackFrame(char[] sPayLoad, char[] sFrame, int vFrame[WebsocketFrame])
{
	int length = vFrame[PAYLOAD_LEN];
	
	// We don't split frames (yet), so FIN is always 1.
	switch(vFrame[OPCODE])
	{
		case FrameType_Text:
		{
			sFrame[0] = 129; // (1<<0)|(1<<7) - Text-Frame (10000001):
		}
		case FrameType_Close:
		{
			sFrame[0] = 136; // (1<<3)|(1<<7) -  Close-Frame (10001000):
			length += 2; // Remember the 2byte close reason
		}
		case FrameType_Ping:
		{
			sFrame[0] = 137; // (1<<0)|(1<<3)|(1<<7) -  Ping-Frame (10001001):
		}
		case FrameType_Pong:
		{
			sFrame[0] = 138; // (1<<1)|(1<<3)|(1<<7) -  Pong-Frame (10001010):
		}
		default:
		{
			LogError("Trying to send frame with unknown opcode = %d", view_as<int>(vFrame[OPCODE]));
			return false;
		}
	}
	
	int iOffset;
	
	// Add the length "byte" (7bit). We're only sending unmasked messages
	if(length > 65535)
	{
		sFrame[1] = 127;
		char sLengthBin[65];
		char sByte[9];
		
		Format(sLengthBin, 65, "%064b", length);
		for(int i = 0, j = 2; j <= 10; i++)
		{
			if(i && !(i%8))
			{
				sFrame[j] = bindec(sByte);
				Format(sByte, 9, "");
				j++;
			}
			Format(sByte, 9, "%s%s", sByte, sLengthBin[i]);
		}
		
		// the most significant bit MUST be 0
		if(sFrame[2] > 127)
		{
			LogError("Can't send frame. Too much data.");
			return false;
		}
		iOffset = 9;
	}
	else if(length > 125)
	{
		sFrame[1] = 126;
		if(length < 256)
		{
			sFrame[2] = 0;
			sFrame[3] = length;
		}
		else
		{
			char sLengthBin[17];
			char sByte[9];
			
			Format(sLengthBin, 17, "%016b", length);
			for(int i = 0, j = 2; i <= 16; i++)
			{
				if(i && !(i%8))
				{
					sFrame[j] = bindec(sByte);
					Format(sByte, 9, "");
					j++;
				}
				Format(sByte, 9, "%s%s", sByte, sLengthBin[i]);
			}
		}
		iOffset = 4;
	}
	else
	{
		sFrame[1] = length;
		iOffset = 2;
	}
	
	// Make sure we didn't set the MASK bit by accident..
	sFrame[1] &= ~(1<<7);
	vFrame[MASK] = 0;
	
	// We got a closing reason. Add it right in front of the payload.
	if(vFrame[OPCODE] == FrameType_Close && vFrame[CLOSE_REASON] != -1)
	{
		char sCloseReasonBin[17];
		char sByte[9];
		
		Format(sCloseReasonBin, 17, "%016b", vFrame[CLOSE_REASON]);
		for(int i = 0, j = iOffset; i <= 16; i++)
		{
			if(i && !(i%8))
			{
				sFrame[j] = bindec(sByte);
				Format(sByte, 9, "");
				j++;
			}
			Format(sByte, 9, "%s%s", sByte, sCloseReasonBin[i]);
		}
		iOffset += 2;
	}
	
	// Add the payload at the end.
	strcopy(sFrame[iOffset], length+iOffset, sPayLoad);
	
	return true;
}

// Close the connection by initiating the connection close handshake with the CLOSE opcode
void CloseConnection(int iIndex, int iCloseReason, char[] sPayLoad)
{
	int vFrame[WebsocketFrame];
	vFrame[OPCODE] = FrameType_Close;
	vFrame[CLOSE_REASON] = iCloseReason;
	vFrame[PAYLOAD_LEN] = strlen(sPayLoad);
	SendWebsocketFrame(iIndex, sPayLoad, vFrame);
	g_hChildSocketReadyState.Set(iIndex, State_Closing);
	
	Handle hReadyStateChangeForward = g_hChildReadyStateChangeForwards.Get(iIndex);
	
	// Inform the other plugins of the change.
	Call_StartForward(hReadyStateChangeForward);
	Call_PushCell(g_hChildSocketIndexes.Get(iIndex));
	Call_PushCell(g_hChildSocketReadyState.Get(iIndex));
	Call_Finish();
}

stock void Debug(int iDebugLevel, char[] fmt, any ...)
{
#if DEBUG > 0
	if(iDebugLevel > DEBUG)
		return;
	char sBuffer[512];
	VFormat(sBuffer, sizeof(sBuffer), fmt, 3);
	//LogToFile(g_sLog, sBuffer);
	LogMessage(sBuffer);
#endif
}

stock int GetIndexOfMasterSocket(Handle socket)
{
	int iSize = g_hMasterSockets.Length;
	for(int i = 0; i < iSize; i++)
	{
		if(g_hMasterSockets.Get(i) == socket)
			return i;
	}
	return -1;
}

stock int GetIndexOfChildSocket(Handle socket)
{
	int iSize = g_hChildSockets.Length;
	for(int i = 0; i < iSize; i++)
	{
		if(g_hChildSockets.Get(i) == socket)
			return i;
	}
	return -1;
}

stock int bindec(const char[] sBinary)
{
	int ret, len = strlen(sBinary);
	for(int i = 0; i < len; i++)
	{
		ret = ret<<1;
		if(sBinary[i] == '1')
			ret |= 1;
	}
	return ret;
}

stock bool IsPluginStillLoaded(Handle plugin)
{
	Handle hIt = GetPluginIterator();
	Handle hPlugin;
	bool bPluginLoaded;
	
	while(MorePlugins(hIt))
	{
		hPlugin = ReadPlugin(hIt);
		if(hPlugin == plugin && GetPluginStatus(hPlugin) == Plugin_Running)
		{
			bPluginLoaded = true;
			break;
		}
	}
	hIt.Close();
	return bPluginLoaded;
}