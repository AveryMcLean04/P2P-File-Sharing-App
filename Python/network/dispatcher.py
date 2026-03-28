from typing import Dict, Any

class MessageDispatcher:
    """
    Acts as the central routing hub for all incoming network traffic.
    
    Responsibilities:
    1. Security Filtering: Ensures non-public messages only pass through if 
       a secure session is established.
    2. Protocol Mapping: Maps JSON message types to specific PeerLogic methods.
    3. Error Isolation: Prevents a single malformed message from crashing 
       the network listener thread.
    """
    
    def __init__(self, app, logic):
        """
        Initializes the dispatcher with application context and business logic.
        
        :param app: The main SecureP2PApp instance.
        :param logic: The PeerLogic instance where protocol handling is defined.
        """
        self.app = app
        self.logic = logic

    def handle(self, message: Dict[str, Any], addr: tuple) -> None:
        """
        Parses an incoming message dictionary and routes it to the correct handler.
        
        :param message: The deserialized JSON message.
        :param addr: The (IP, Port) tuple of the sender.
        """
        m_type = message.get("type")
        sender = message.get("sender")
        payload = message.get("payload", {})

        PUBLIC_TYPES = {
            "HANDSHAKE_INIT",
            "HANDSHAKE_RESPONSE",
            "KEY_MIGRATION_NOTIFY",
            "PEER_LEFT"
        }

        # --- Security Gate ---
        session = self.app.active_sessions.get(sender)
        is_secure = session and session.get("status") == "SECURE-SESSION"

        if m_type not in PUBLIC_TYPES and not is_secure:
            self.app.log("security", f"Blocked {m_type} from {sender}: Secure session required.")
            return

        # --- Handler Mapping ---
        handlers = {
            # Auth & Key Exchange
            "HANDSHAKE_INIT":       lambda: self.logic.process_handshake_init(sender, payload, addr),
            "HANDSHAKE_RESPONSE":   lambda: self.logic.process_handshake_response(sender, payload),
            "KEY_MIGRATION_NOTIFY": lambda: self.logic.process_key_migration(sender, payload),

            # File Management (Core)
            "FILE_LIST_REQUEST":    lambda: self.logic.handle_list_request(sender),
            "FILE_LIST_RESPONSE":   lambda: self.logic.process_file_list_response(sender, payload),
            "TRANSFER_REQUEST":     lambda: self.logic.handle_transfer_request(sender, payload),
            "PUSH_PROPOSAL":        lambda: self.logic.handle_push_proposal(sender, payload),
            "TRANSFER_ACCEPT":      lambda: self.logic.handle_transfer_accept(sender, payload),
            
            # File Feedback & Synchronization
            "TRANSFER_REJECT":      lambda: self.logic.handle_transfer_reject(sender, payload),
            "TRANSFER_ERROR":       lambda: self.app.log("error", f"Transfer error from {sender}: {payload.get('message')}"),
            "FILE_REMOVAL_NOTIFY":  lambda: self.logic.process_file_removal(sender, payload),

            # Redundancy & Search
            "REDUNDANCY_QUERY":     lambda: self.logic.handle_redundancy_query(sender, payload),
            "REDUNDANCY_OFFER":     lambda: self.logic.handle_redundancy_offer(sender, payload),

            # Communication & System
            "CHAT_MESSAGE":         lambda: self.logic.process_chat_message(sender, payload),
            "SECURITY_ALERT":       lambda: self.app.display_security_error(sender, payload),
            "PEER_LEFT":            lambda: self.logic.handle_peer_left(sender, payload)
        }

        if m_type in handlers:
            try:
                handlers[m_type]()
            except Exception as e:
                self.app.log("error", f"Protocol error processing {m_type} from {sender}: {e}")
        else:
            self.app.log("network", f"Unknown message type: {m_type}")