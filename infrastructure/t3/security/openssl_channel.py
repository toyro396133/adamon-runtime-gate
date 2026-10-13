"""Explicit pyOpenSSL backend: TLS1.3 exporter and pinned direct-CA binding.
Unknown critical extension bypass is permitted ONLY for our exact binding OID
and a separately verified directly issued leaf. All other failures reject.
"""
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from .protocol import Denied, spki_digest

def verify_bound_leaf(cert, ca, oid, expected_binding, expected_spki):
    cert.verify_directly_issued_by(ca)
    now=datetime.now(timezone.utc)
    if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc: raise Denied('certificate time')
    if cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca: raise Denied('client CA')
    if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value: raise Denied('client EKU')
    if not cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature: raise Denied('client usage')
    extension=cert.extensions.get_extension_for_oid(oid)
    if not extension.critical or extension.value.value!=expected_binding: raise Denied('binding')
    if spki_digest(cert.public_key())!=expected_spki: raise Denied('SPKI')
    for ext in cert.extensions:
        if ext.critical and isinstance(ext.value,x509.UnrecognizedExtension) and ext.oid!=oid:
            raise Denied('unknown critical extension')
    return cert.public_key()

def server_context(server_cert, server_key, pinned_ca, oid, expected_binding, expected_spki):
    from OpenSSL import SSL,crypto
    ctx=SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_3_VERSION);ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_certificate(server_cert)
    ctx.use_privatekey(server_key)
    ctx.get_cert_store().add_cert(crypto.X509.from_cryptography(pinned_ca))
    def callback(conn, certificate, error, depth, valid):
        try:
            cert=certificate.to_cryptography()
            if depth==0:
                verify_bound_leaf(cert,pinned_ca,oid,expected_binding,expected_spki)
                # OpenSSL error34 is exactly unhandled critical extension.
                return bool(valid or error==34)
            return bool(valid and depth==1 and cert.fingerprint(hashes.SHA256())==pinned_ca.fingerprint(hashes.SHA256()))
        except Exception: return False
    ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT,callback)
    return ctx

def accept(context, raw_socket, record, pinned_ca, oid, expected_binding, expected_spki):
    from OpenSSL import SSL
    record.authenticate(raw_socket)
    conn=SSL.Connection(context,raw_socket);conn.set_accept_state()
    import select,time
    raw_socket.setblocking(False);deadline=time.monotonic()+30
    while True:
        try:conn.do_handshake();break
        except (SSL.WantReadError,SSL.WantWriteError) as exc:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise Denied('TLS handshake deadline')
            read=[raw_socket] if isinstance(exc,SSL.WantReadError) else []
            write=[raw_socket] if isinstance(exc,SSL.WantWriteError) else []
            readable,writable,_=select.select(read,write,[],remaining)
            if not readable and not writable:raise Denied('TLS handshake deadline')
    raw_socket.setblocking(True)
    if conn.get_protocol_version_name()!='TLSv1.3': raise Denied('TLS version')
    cert=conn.get_peer_certificate().to_cryptography()
    public=verify_bound_leaf(cert,pinned_ca,oid,expected_binding,expected_spki)
    record.authenticate(raw_socket)
    import hashlib
    exported=conn.export_keying_material(b'ADAMON-P4V3-CHANNEL',32,None)
    return conn,public,hashlib.sha256(exported).hexdigest()
