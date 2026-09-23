package audit

import "time"

type Entry struct {
Seq       uint64
Timestamp time.Time
TenantID  string
Actor     string
Action    string
Resource  string
Outcome   string
PrevHash  []byte
Hash      []byte
HMAC      []byte
}