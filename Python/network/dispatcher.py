class MessageDispatcher:
    def __init__(self, app, logic):
        """
        Routes incoming network messages to the logic manager.
        :param app: The main SecureP2PApp instance (for logging/config)
        :param logic: The PeerLogic instance (for protocol handling)
        """
        self.app = app
        self.logic = logic

    def handle(self, message, addr):
        m_type = message.get("type")
        sender = message.get("sender")
        payload = message.get("payload")

        # Map message types directly to Logic methods
        handlers = {
            "HANDSHAKE_INIT":    lambda: self.logic.process_handshake_init(sender, payload, addr),
            "HANDSHAKE_RESPONSE":lambda: self.logic.process_handshake_response(sender, payload),
            "FILE_LIST_REQUEST": lambda: self.logic.handle_list_request(sender),
            "FILE_LIST_RESPONSE":lambda: self.logic.process_list_response(sender, payload),
            "TRANSFER_REQUEST":  lambda: self.logic.handle_transfer_request(sender, payload),
            "TRANSFER_ACCEPT":   lambda: self.logic.handle_transfer_accept(sender, payload),
            "FILE_DATA_PACKET":  lambda: self.logic.process_file_transfer(sender, payload),
            "REDUNDANCY_QUERY":  lambda: self.logic.handle_redundancy_query(sender, payload),
            "REDUNDANCY_OFFER":  lambda: self.logic.handle_redundancy_offer(sender, payload),
            "TRANSFER_REJECT":   lambda: self.app.log("transfer", f"{sender} rejected the transfer."),
        }

        if m_type in handlers:
            handlers[m_type]()
        else:
            self.app.log("network", f"Unknown message type from {sender}: {m_type}")