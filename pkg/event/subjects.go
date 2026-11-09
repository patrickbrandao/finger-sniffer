package event

// Subjects do barramento (fs.v1.<origem>.<tipo>), conforme eventbus/nats/asyncapi.yaml 0.3.0.
const (
	SubjectCapturePacket      = "fs.v1.capture.packet"
	SubjectWebTLSClientHello  = "fs.v1.web.tls.client_hello"
	SubjectWebTLSHandshake    = "fs.v1.web.tls.handshake"
	SubjectWebHTTP1Request    = "fs.v1.web.http1.request"
	SubjectWebHTTP2Connection = "fs.v1.web.http2.connection"
	SubjectWebHTTP2Stream     = "fs.v1.web.http2.stream"
	SubjectWebHTTP3Connection = "fs.v1.web.http3.connection"
	SubjectWebHTTP3Request    = "fs.v1.web.http3.request"
	SubjectWebWebSocketFrame  = "fs.v1.web.websocket.frame"
	SubjectWebStreamBytes     = "fs.v1.web.stream.bytes"
	SubjectWebRawSession      = "fs.v1.web.raw.session"
	SubjectRawSession         = "fs.v1.raw.session"
	SubjectRawRead            = "fs.v1.raw.read"
	SubjectDNSQuery           = "fs.v1.dns.query"
	SubjectHeartbeat          = "fs.v1.svc.heartbeat"
	SubjectDNSACMESet         = "fs.v1.dns.acme.set"   // request/reply NATS core, fora do stream
	SubjectDNSACMEClear       = "fs.v1.dns.acme.clear" // request/reply NATS core, fora do stream
	SubjectStoreConnID        = "fs.v1.store.conn_id"  // request/reply NATS core, fora do stream
	subjectCaptureWildcard    = "fs.v1.capture.>"
	subjectWebWildcard        = "fs.v1.web.>"
	subjectRawWildcard        = "fs.v1.raw.>"
	subjectServiceWildcard    = "fs.v1.svc.>"
)

// StreamSubjects é a lista explícita de subjects de eventos assinada pelo stream FS_EVENTS (ADR 0017). Os
// request/reply (fs.v1.dns.acme.*, fs.v1.store.conn_id) ficam de fora: senão o JetStream responderia um PubAck
// no inbox da requisição. Um subject de evento novo entra aqui no mesmo PR que o cria no asyncapi.yaml.
var StreamSubjects = []string{
	subjectCaptureWildcard,
	subjectWebWildcard,
	subjectRawWildcard,
	SubjectDNSQuery,
	subjectServiceWildcard,
}

// EventSubjects lista todos os subjects de eventos (os que o stream guarda).
var EventSubjects = []string{
	SubjectCapturePacket, SubjectWebTLSClientHello, SubjectWebTLSHandshake, SubjectWebHTTP1Request,
	SubjectWebHTTP2Connection, SubjectWebHTTP2Stream, SubjectWebHTTP3Connection, SubjectWebHTTP3Request,
	SubjectWebWebSocketFrame, SubjectWebStreamBytes, SubjectWebRawSession, SubjectRawSession, SubjectRawRead,
	SubjectDNSQuery, SubjectHeartbeat,
}

// RequestSubjects lista os request/reply NATS core (fora do stream).
var RequestSubjects = []string{SubjectDNSACMESet, SubjectDNSACMEClear, SubjectStoreConnID}
