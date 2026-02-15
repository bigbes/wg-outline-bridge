package statsdb

// WGPeerSnapshot is the current UAPI snapshot for a single peer (input to flush).
type WGPeerSnapshot struct {
	PublicKey        string
	Name             string
	LastHandshakeSec int64
	RxBytes          int64
	TxBytes          int64
}

// WGPeerRecord is the persisted cumulative record (output from reads).
type WGPeerRecord struct {
	Name              string
	LastHandshakeUnix int64
	RxTotal           int64
	TxTotal           int64
	ConnectionsTotal  int64
}

// MTSecretSnapshot is the current in-memory snapshot for an MTProxy secret.
type MTSecretSnapshot struct {
	SecretHex          string
	LastConnectionUnix int64
	Connections        int64
	BytesC2B           int64
	BytesB2C           int64
	BackendDialErrors  int64
}

// MTSecretRecord is the persisted cumulative record for an MTProxy secret.
type MTSecretRecord struct {
	LastConnectionUnix     int64
	ConnectionsTotal       int64
	BytesC2BTotal          int64
	BytesB2CTotal          int64
	BackendDialErrorsTotal int64
}

// AllowedUser represents an authorized Telegram user stored in the database.
type AllowedUser struct {
	UserID    int64
	Username  string
	FirstName string
	LastName  string
	PhotoURL  string
	CreatedAt int64
}
