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
        payload = message.get("payload")

        # Routing table to PeerLogic methods
        handlers = {
            # --- Auth & Key Exchange (Req 2, 6, 8) ---
            "HANDSHAKE_INIT":     lambda: self.logic.process_handshake_init(sender, payload, addr),
            "HANDSHAKE_RESPONSE": lambda: self.logic.process_handshake_response(sender, payload),
            "KEY_MIGRATION":      lambda: self.logic.process_key_migration(sender, payload),

            # --- File Management (Req 3, 4, 5) ---
            "FILE_LIST_REQUEST":  lambda: self.logic.handle_list_request(sender),
            "FILE_LIST_RESPONSE": lambda: self.logic.process_list_response(sender, payload),
            "TRANSFER_REQUEST":   lambda: self.logic.handle_transfer_request(sender, payload),
            "TRANSFER_ACCEPT":    lambda: self.logic.handle_transfer_accept(sender, payload),
            "TRANSFER_REJECT":    lambda: self.app.log("transfer", f"{sender} denied the file transfer."),
            "FILE_DATA_PACKET":   lambda: self.logic.process_file_transfer(sender, payload),

            # --- Redundancy & Search (Req 5) ---
            "REDUNDANCY_QUERY":   lambda: self.logic.handle_redundancy_query(sender, payload),
            "REDUNDANCY_OFFER":   lambda: self.logic.handle_redundancy_offer(sender, payload),

            # --- Communication & Errors (Req 7, 10) ---
            "CHAT_MESSAGE":       lambda: self.logic.process_chat_message(sender, payload),
            "SECURITY_ALERT":     lambda: self.app.display_security_error(sender, payload),
            "TRANSFER_ERROR":     lambda: self.app.log("error", f"Transfer failed with {sender}: {payload}")
        }

        if m_type in handlers:
            try:
                handlers[m_type]()
            except Exception as e:
                # Requirement 10: Inform the user of processing failures
                self.app.log("error", f"Protocol error processing {m_type} from {sender}: {e}")
        else:
            self.app.log("network", f"Unknown message type: {m_type}")