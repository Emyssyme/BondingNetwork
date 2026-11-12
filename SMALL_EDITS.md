# Edits mici în fișiere existente (nu necesită fișier nou)

## core/protocol.py — adaugă `header_bytes()` și refolosește-l în `serialize()`
```python
    def header_bytes(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT, MAGIC, self.version, int(self.pkt_type), self.session_id,
            self.path_id, int(self.flags), b'\x00\x00', self.seq_num
        )

    def serialize(self) -> bytes:
        return self.header_bytes() + self.payload
```

## core/prober.py — `generate_probes`: seq-ul probei devine seq_num (nonce unic pe probe)
```diff
-                seq_num=0,
+                seq_num=seq,
```

## core/reorder.py — blocker #5: nu mai forța sărirea peste gap-uri
```diff
     def flush_expired(self) -> List[bytes]:
         if not self.heap:
             return []
-        return self._drain(time.time(), force_expired=True)
+        return self._drain(time.time())
```

## core/adapter.py — simularea de căi OFF implicit
```diff
-os.environ.get("MYSPEEDIFY_SIMULATE_PATHS", "1") == "1"
+os.environ.get("MYSPEEDIFY_SIMULATE_PATHS", "0") == "1"
```

## server/setup_linux.sh — secret generat local, psutil, fără secret în repo
```diff
-/opt/myspeedify/venv/bin/pip install cryptography
+/opt/myspeedify/venv/bin/pip install cryptography psutil
+
+install -d -m 700 /etc/myspeedify
+if [ ! -f /etc/myspeedify/secret ]; then
+  (umask 077; head -c 32 /dev/urandom | base64 > /etc/myspeedify/secret)
+fi
```
și în unitatea systemd, sub `[Service]`:
```diff
+Environment=MYSPEEDIFY_SECRET_FILE=/etc/myspeedify/secret
```
iar la final, ca să-l copiezi pe client:
```diff
+echo "  Secret client: $(cat /etc/myspeedify/secret)"
```

## tests/test_core.py
Șterge `test_crypto_aead` (folosea `from_passphrase`, eliminat). Îl înlocuiește `tests/test_handshake.py`.
