from dnserver import DNSServer
import toml


class Record():
    RECORD_SQUELETON = "[[zones]]\nhost = '%s'\ntype = '%s'\nanswer = '%s'\n"
    
    def __init__(self, **kwargs) -> None:
        self.host = kwargs.get('host', None)
        self.type = kwargs.get('type', None)
        self.answer = kwargs.get('answer', None)

    def __repr__(self) -> str:
        return f"Record(host={self.host}, type={self.type}, answer={self.answer})"

    def __str__(self) -> str:
        return Record.RECORD_SQUELETON % (self.host, self.type, self.answer)
        


class ACME_DNS():

    DNS_TABLE_TOML_PATH = 'src/dns/acme_dns.toml'
    PORT = 5053
    
    def __init__(self) -> None:

        with open(ACME_DNS.DNS_TABLE_TOML_PATH, 'r') as f:
            list_of_zones: list[dict[str,str]] = toml.load(f)['zones']

        self.zones: dict[str, Record] = {}
        for zone in list_of_zones:
            key = ACME_DNS._record_key(zone['host'], zone['type'])
            self.zones[key] = Record(**zone)

        self.server: DNSServer = None
        
    def is_running(self):
        return  self.server is not None and self.server.is_running
            
    def dump_records(self, file_path: str = DNS_TABLE_TOML_PATH):
        with open(file_path, 'w') as f:
            for _, record in self.zones.items():
                f.write(str(record))
                f.write('\n')
    
    def start(self):
        # Late creation of the server to allow the dump_records new records to be called before
        self.server = DNSServer.from_toml(ACME_DNS.DNS_TABLE_TOML_PATH, port=ACME_DNS.PORT, upstream=None)
        self.server.start()

    def stop(self):
        if self.server and self.server.is_running:
            self.server.stop()
        

    def _reload(self):
        self.dump_records()
        if self.is_running():
            self.stop()
            self.start()

    def _record_key(hostname: str, record_type: str):
        key = f"{hostname}|{record_type}"
        return key
        
    def serve_record(self, hostname: str, record_type: str, record_answer: str,):
        record_key = ACME_DNS._record_key(hostname, record_type)
        self.zones[record_key] = Record(host=hostname, type=record_type, answer=record_answer)
        self._reload()

    def remove_record(self, hostname: str, record_type: str):
        record_key = ACME_DNS._record_key(hostname, record_type)
        if record_key in self.zones:
            del self.zones[record_key]
            self._reload()    
    
    

# import threading, signal
# if __name__ == '__main__':

#     acme_dns = ACME_DNS()
#     # acme_dns.serve_record('new.example.com', 'A', '0.1.2.3')  
#     acme_dns.serve_record('new.example.com', 'TXT', 'updated new text')  
#     acme_dns.start()

#     cli_running = True
#     while cli_running:
#         print("Enter command: add, remove, exit")
#         command = input()
#         match command:
#             case 'add':
#                 print("Enter hostname, type, answer to be added")
#                 hostname, record_type, record_answer = input().split()
#                 acme_dns.serve_record(hostname, record_type, record_answer) 

#             case 'remove':
#                 print("Enter hostname, type to be removed")
#                 hostname, record_type = input().split()
#                 acme_dns.remove_record(hostname, record_type)

#             case 'reload':
#                 acme_dns._reload()

#             case 'exit':
#                 cli_running = False
#                 acme_dns.stop()
#                 break
    
#     # Create an event to control when to wake up
#     termination_event = threading.Event()

#     def sigterm_handler(*args):    
#         print("Stop serving...")
#         acme_dns.stop()    
#         termination_event.set()
        

#     # Register the SIGTERM signal handler
#     signal.signal(signal.SIGTERM, sigterm_handler)
#     signal.signal(signal.SIGINT, sigterm_handler)
#     signal.signal(signal.SIGQUIT, sigterm_handler)

#     print("SERVING until SIGTERM|SIGINT is received...")

#     # Wait until the termination event is set by the signal handler
#     termination_event.wait()
    
# COMMAND ---------- dig @localhost -p 5053 example.com A