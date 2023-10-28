import hashlib
from operator import ne
import re
from tracemalloc import start
from dnserver import DNSServer
import signal
import threading

import toml


class ACME_DNS():

    DNS_TABLE_TOML_PATH = 'src/dns/acme_dns.toml'
    PORT = 5053

    RECORD_SQUELETON = "[[zones]]\nhost = '%s'\ntype = '%s'\nanswer = '%s'\n\n"

    offset_tables = {}
    
    def __init__(self) -> None:
        self._file = open(self.DNS_TABLE_TOML_PATH, 'a+')
        self.__populate_offset_tables()
        


    def __populate_offset_tables(self):
        self._file.seek(0)
        cursor = self._file.tell()
        line = self._file.readline()
        while line:
            if line.startswith('[[zones]]'):
                hostname = re.search(r"host = '(.*?)'", self._file.readline()).group(0)
                record_type = re.search(r"type = '(.*?)'", self._file.readline()).group(0)
                record_key = ACME_DNS.__record_key(hostname, record_type)
                self.offset_tables[record_key] = cursor

                print('Found record: ', hostname, record_type, cursor)

            cursor = self._file.tell()
            line = self._file.readline()
                
        self._file.seek(0,2)

    def start(self):
        self.server = DNSServer.from_toml(ACME_DNS.DNS_TABLE_TOML_PATH, port=ACME_DNS.PORT, upstream=None)

    def stop(self):
        if self.server and self.server.is_running:
            self.server.stop()
            
        if not self._file.closed:
            self._file.close()

    def _reload(self):
        if not self._file.closed:
            self._file.close()

        if self.server.is_running:
            self.server.stop()
        self.server.start()

    def __record_key(hostname: str, record_type: str):
        key = hashlib.sha256((f"{hostname}|{record_type}").encode('utf-8')).hexdigest()
        return key
        
    def serve_record(self, hostname: str, record_type: str, record_answer: str,):
        record = ACME_DNS.RECORD_SQUELETON % (hostname, record_type, record_answer)
        record_key = ACME_DNS.__record_key(hostname, record_type)
        self.offset_tables[record_key] = self._file.tell()
        self._file.write(record)
        self._file.flush()
        # self._reload()

    def remove_record(self, hostname: str, record_type: str):
        record_key = ACME_DNS.__record_key(hostname, record_type)
        offset = self.offset_tables.get(record_key, None)
        self._file.seek(offset) 
        self._file.writelines(['erase']*4)
        self._file.flush()
        self._file.seek(0, 2) # Seek to the end of the file
        
        
        

    def replace_record(self, hostname: str, record_type: str, new_record_answer: str):
        record_key = ACME_DNS.__record_key(hostname, record_type)
        offset = self.offset_tables.get(record_key, None)
        if not offset:
            raise Exception('Record not found')
        
        self._file.seek(offset) 
        # self._file.writelines(['']*3)

        new_record = ACME_DNS.RECORD_SQUELETON % (hostname, record_type, new_record_answer)
        self._file.write(new_record)
        self._file.flush()
        # self._file.seek(0, 2) # Seek to the end of the file
        


if __name__ == '__main__':
    acme_dns = ACME_DNS()
    # acme_dns.start()
    acme_dns.serve_record('new.example.com', 'A', '0.1.2.3')  
    acme_dns.replace_record('new.example.com', 'A', 'pawned')  
    # acme_dns.remove_record('new.example.com', 'A')  

    # with open('src/dns/acme_dns.toml', 'r') as f:
    #     t = toml.load(f)

    # print(t)
    


# if __name__ == '__main__':

#     server = DNSServer.from_toml('src/dns/acme_dns.toml', port=5053, upstream=None)
#     server.start()
#     assert server.is_running
    
#     # Create an event to control when to wake up
#     termination_event = threading.Event()

#     def sigterm_handler(*args):    
#         print("Stop serving...")
#         server.stop()    
#         termination_event.set()
        

#     # Register the SIGTERM signal handler
#     signal.signal(signal.SIGTERM, sigterm_handler)
#     signal.signal(signal.SIGINT, sigterm_handler)
#     signal.signal(signal.SIGQUIT, sigterm_handler)

#     print("SERVING until SIGTERM|SIGINT is received...")

#     # Wait until the termination event is set by the signal handler
#     termination_event.wait()
    
