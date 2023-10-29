import json
import os
from typing import Optional


class ACME_DB:
    def __init__(self, db_path: str):
        if db_path is None or os.path.exists(db_path) is False:
            raise ValueError("ACME_DB path must not be None")

        self.db_path = db_path
        self.table = {}

    def add(self, key: str, value: str):
        self.table[key] = value
        with open(self.db_path, "w") as f:
            json.dump(self.table, f)
            f.flush()

    def remove(self, key: str):
        self.table.pop(key)
        with open(self.db_path, "w") as f:
            json.dump(self.table, f)
            f.flush()

    def get(self, key: str) -> Optional[str]:
        return self.table.get(key)

    def close(self):
        with open(self.db_path, "w") as f:
            f.write("{}")
