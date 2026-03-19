import sys

class AppCLI:
    def __init__(self, app):
        """
        Connects user input to the SecureP2PApp engine and Logic manager.
        """
        self.app = app
        
        # We point these to the 'logic' component to keep main.py clean
        self.commands = {
            "help":    {"func": self.show_help,           "desc": "Show all available commands"},
            "list":    {"func": self.app.logic.cmd_list,  "desc": "List discovered network peers (mDNS)"},
            "find":    {"func": self.app.logic.cmd_find,  "desc": "Search for offline peer's files"},
            "connect": {"func": self.app.logic.cmd_connect, "desc": "Establish secure session (PFS Handshake)"},
            "fetch":   {"func": self.app.logic.cmd_fetch,   "desc": "Request file list from a peer"},
            "send":    {"func": self.app.logic.cmd_send,    "desc": "Send file with consent"},
            "rotate":  {"func": self.app.logic.cmd_rotate,  "desc": "Rotate identity keys"},
            "exit":    {"func": self.app.shutdown,         "desc": "Safely shut down"}
        }

    def print_banner(self):
        banner = f" SECURE P2P: {self.app.config.user_id} "
        print(f"\n{'='*50}\n{banner:^50}\n{'='*50}")

    def show_help(self, *args):
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 45)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12} | {info['desc']}")

    def run_loop(self):
        """The main interactive loop for the user."""
        self.print_banner()
        while True:
            try:
                user_input = input(f"\n{self.app.config.user_id} > ").strip().split()
                if not user_input:
                    continue
                
                cmd_name = user_input[0].lower()
                args = user_input[1:]

                if cmd_name in self.commands:
                    # Executes the logic method assigned to the command
                    self.commands[cmd_name]["func"](*args)
                    if cmd_name == "exit":
                        break
                else:
                    print(f"[-] Unknown command: {cmd_name}. Type 'help' for options.")
            
            except (EOFError, KeyboardInterrupt):
                self.app.shutdown()
                break