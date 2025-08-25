"""Implementation of the logic for representing the requests and logging them.

This module defines two classes:

* `Request` – a simple container used throughout the firewall to carry request
  attributes and eventually a dictionary of detected threats;
* `DBController` – a thin wrapper around an SQLite database for persisting
  incoming requests and their associated threat labels.  Each request is
  serialised as JSON in the `requests_log/` directory and the metadata is
  recorded in two tables (`logs` and `threats`).

The database schema is initialised externally (see the original project) and
is compatible with the dashboard shipped with this repository.
"""

import datetime
import sqlite3
import pandas as pd
import json
import os
from typing import Optional, Dict, Any


class Request:
    """Represents a single HTTP request observed by the firewall.

    The object holds all relevant fields extracted from a packet: origin
    address, host header, request path, body, HTTP method, arbitrary
    headers, and a dictionary mapping detected threat types to the location
    (e.g. 'Body' or 'Cookie').  All attributes default to ``None`` until
    they are set by the sniffer.
    """

    def __init__(
        self,
        id: Optional[int] = None,
        timestamp: Optional[datetime.datetime] = None,
        origin: Optional[str] = None,
        host: Optional[str] = None,
        request: Optional[str] = None,
        body: Optional[str] = None,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        threats: Optional[Dict[str, str]] = None,
    ) -> None:
        self.id = id
        self.timestamp = timestamp
        self.origin = origin
        self.host = host
        self.request = request
        self.body = body
        self.method = method
        self.headers = headers or {}
        self.threats = threats or {}

    def to_json(self) -> str:
        """Serialise the request to a JSON string containing all
        non‑empty fields and headers.  This method is used when dumping
        requests to disk for later inspection."""
        output: Dict[str, Any] = {}
        if self.request:
            output['request'] = self.request
        if self.body:
            output['body'] = self.body
        # Include headers without mangling their names
        for header, value in (self.headers or {}).items():
            output[header] = value
        return json.dumps(output)


class DBController:
    """A simple interface for persisting and retrieving request logs.

    Instances of this class manage a SQLite connection to the `log.db`
    database.  Requests are inserted into the `logs` table and each
    individual threat is inserted into the `threats` table.  When
    persisting a request the JSON representation is also written to
    `requests_log/<id>.json`.
    """

    def __init__(self, db_path: str = "log.db") -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def save(self, obj: Request) -> None:
        if not isinstance(obj, Request):
            raise TypeError("Object should be a Request!")
        cursor = self.conn.cursor()
        # assign a timestamp when saving
        obj.timestamp = datetime.datetime.now()
        cursor.execute(
            "INSERT INTO logs (timestamp, origin, host, method) VALUES (?, ?, ?, ?)",
            (obj.timestamp, obj.origin, obj.host, obj.method),
        )
        obj.id = cursor.lastrowid
        # write JSON representation to file
        file_name = f"{obj.id}.json"
        file_path = os.path.join('requests_log', file_name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(json.loads(obj.to_json()), f)
        # insert associated threats
        for threat, location in obj.threats.items():
            cursor.execute(
                "INSERT INTO threats (log_id, threat_type, location) VALUES (?, ?, ?)",
                (obj.id, threat, location),
            )
        self.conn.commit()

    def _create_entry(self, row: sqlite3.Row) -> Dict[str, Any]:
        entry = dict(row)
        entry['Link'] = f"[Review](http://127.0.0.1:8050/review/{entry['id']})"
        return entry

    def read_all(self) -> pd.DataFrame:
        """Return a DataFrame with all stored requests and associated threats."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id")
        results = cursor.fetchall()
        data = [self._create_entry(row) for row in results]
        return pd.DataFrame(data)

    def _create_single_entry(self, row: sqlite3.Row) -> list:
        return [row['threat_type'], row['location']]

    def read_request(self, id: int) -> tuple:
        """Return metadata and threats for a single request id."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id WHERE l.id = ?",
            (id,),
        )
        results = cursor.fetchall()
        log: Dict[str, Any] = {}
        if results:
            first = results[0]
            log['timestamp'] = first['timestamp']
            log['origin'] = first['origin']
            log['host'] = first['host']
            log['method'] = first['method']
        data = [self._create_single_entry(row) for row in results]
        return log, data

    def close(self) -> None:
        self.conn.close()