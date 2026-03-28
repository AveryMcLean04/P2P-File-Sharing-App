class MessageDispatcher:
    def __init__(self, app, logic):
        """
        Routes incoming network messages to PeerLogic.
        Handles data from different languages by expecting standard JSON keys.
        """
        self.app = app
        self.logic = logic

    def handle(self, message, addr):
        m_type = message.get("type")
        sender = message.get("sender")
        payload = message.get("payload", {})

        PUBLIC_TYPES = {
            "HANDSHAKE_INIT", 
            "HANDSHAKE_RESPONSE", 
            "KEY_MIGRATION_NOTIFY", 
            "PEER_LEFT"
        }

        session = self.app.active_sessions.get(sender)
        is_secure = session and session.get("status") == "SECURE-SESSION"

        if m_type not in PUBLIC_TYPES and not is_secure:
            self.app.log("security", f"Blocked {m_type} from {sender}: Secure session required.")
            return

        handlers = {
            # --- Auth & Key Exchange ---
            "HANDSHAKE_INIT":       lambda: self.logic.process_handshake_init(sender, payload, addr),
            "HANDSHAKE_RESPONSE":   lambda: self.logic.process_handshake_response(sender, payload),
            "KEY_MIGRATION_NOTIFY": lambda: self.logic.process_key_migration(sender, payload),

            # --- File Management (Non-Blocking) ---
            "FILE_LIST_REQUEST":    lambda: self.logic.handle_list_request(sender),
            "FILE_LIST_RESPONSE":   lambda: self.logic.process_file_list_response(sender, payload),
            
            # Now queues a pending transfer for the 'accept' command
            "TRANSFER_REQUEST":     lambda: self.logic.handle_transfer_request(sender, payload),
            "PUSH_PROPOSAL":        lambda: self.logic.handle_push_proposal(sender, payload),
            
            # Processes actual encrypted file data
            "TRANSFER_ACCEPT":      lambda: self.logic.handle_transfer_accept(sender, payload),
            
            # Feedback handlers
            "TRANSFER_REJECT":      lambda: self.logic.handle_transfer_reject(sender, payload),
            "TRANSFER_ERROR":       lambda: self.app.log("error", f"Transfer error from {sender}: {payload.get('message')}"),
            "FILE_REMOVAL_NOTIFY":  lambda: self.logic.process_file_removal(sender, payload),

            # --- Redundancy & Search ---
            "REDUNDANCY_QUERY":     lambda: self.logic.handle_redundancy_query(sender, payload),
            "REDUNDANCY_OFFER":     lambda: self.logic.handle_redundancy_offer(sender, payload),

            # --- Communication & System ---
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