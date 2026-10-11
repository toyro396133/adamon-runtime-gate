"""TLS peer proof uses verified handshake certificate, never caller JSON identity."""
import hashlib
import ssl
from cryptography import x509
from .protocol import Denied, spki_digest

def server_context(certfile, keyfile, client_ca):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile,keyfile)
    ctx.load_verify_locations(cafile=client_ca)
    return ctx

def authenticated_channel(tls_socket, process_record, expected_spki, expected_binding_bytes, binding_oid):
    if tls_socket.version()!='TLSv1.3': raise Denied('TLS version')
    process_record.authenticate(tls_socket)
    raw=tls_socket.getpeercert(binary_form=True)
    if not raw: raise Denied('mTLS certificate absent')
    cert=x509.load_der_x509_certificate(raw)
    if spki_digest(cert.public_key())!=expected_spki: raise Denied('SPKI mismatch')
    ext=cert.extensions.get_extension_for_oid(binding_oid)
    if not ext.critical or ext.value.value!=expected_binding_bytes: raise Denied('certificate binding')
    # Python ssl lacks the required RFC5705 exporter on many supported builds.
    # tls-unique is deliberately NOT substituted: no unbound weakened challenge.
    exporter=getattr(tls_socket,'export_keying_material',None)
    if exporter is None: raise Denied('BLOCKED: TLS exporter backend unavailable')
    material=exporter('ADAMON-P4V3-CHANNEL',32,None)
    process_record.verify()
    return cert.public_key(),hashlib.sha256(material).hexdigest()
