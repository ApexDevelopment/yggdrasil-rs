//! TLS settings for peer links. Like yggdrasil-go, nodes present a self-signed
//! certificate for their ed25519 key and skip certificate verification: peers
//! are authenticated by the link handshake that follows.

use std::sync::Arc;

use petrified::types::PrivateKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

/// The DER encoding of an ed25519 key in PKCS#8 is this prefix followed by the seed.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

pub fn pkcs8_der(secret: &PrivateKey) -> Vec<u8> {
	let mut der = PKCS8_ED25519_PREFIX.to_vec();
	der.extend_from_slice(secret.seed());
	der
}

/// Extracts the seed from a PKCS#8 ed25519 key, rejecting anything else.
pub fn seed_from_pkcs8_der(der: &[u8]) -> Option<[u8; 32]> {
	let seed = der.strip_prefix(&PKCS8_ED25519_PREFIX[..])?;
	seed.try_into().ok()
}

/// A self-signed certificate for the node's key, matching the one yggdrasil-go generates.
pub fn self_signed_certificate(
	secret: &PrivateKey,
) -> Result<CertificateDer<'static>, rcgen::Error> {
	let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8_der(secret));
	let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)?;
	let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
	params.distinguished_name = rcgen::DistinguishedName::new();
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		hex::encode(secret.public_key().0),
	);
	params.serial_number = Some(rcgen::SerialNumber::from(vec![1]));
	params.not_after = rcgen::date_time_ymd(9999, 12, 31);
	params.is_ca = rcgen::IsCa::ExplicitNoCa;
	params.key_usages = vec![
		rcgen::KeyUsagePurpose::DigitalSignature,
		rcgen::KeyUsagePurpose::KeyEncipherment,
	];
	params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
	Ok(params.self_signed(&key_pair)?.der().clone())
}

fn provider() -> Arc<CryptoProvider> {
	Arc::new(rustls::crypto::ring::default_provider())
}

/// TLS configurations shared by every TLS-based link type.
#[derive(Clone)]
pub struct TlsConfigs {
	/// TLS 1.2 or 1.3, for `tls`, `wss` and `sockstls`.
	pub client: Arc<ClientConfig>,
	/// TLS 1.3 only.
	pub server: Arc<ServerConfig>,
	pub quic_client: Arc<ClientConfig>,
}

impl TlsConfigs {
	pub fn new(secret: &PrivateKey) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		let certificate = self_signed_certificate(secret)?;
		let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der(secret)));
		let server = ServerConfig::builder_with_provider(provider())
			.with_protocol_versions(&[&rustls::version::TLS13])?
			.with_no_client_auth()
			.with_single_cert(vec![certificate], key)?;
		Ok(TlsConfigs {
			client: Arc::new(client_config(&[
				&rustls::version::TLS12,
				&rustls::version::TLS13,
			])?),
			server: Arc::new(server),
			quic_client: Arc::new(client_config(&[&rustls::version::TLS13])?),
		})
	}
}

fn client_config(
	versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<ClientConfig, rustls::Error> {
	let provider = provider();
	let verifier = AcceptAnyCertificate {
		algorithms: provider.signature_verification_algorithms,
	};
	Ok(ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(versions)?
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(verifier))
		.with_no_client_auth())
}

/// Accepts any certificate, but still checks the handshake signature against it.
#[derive(Debug)]
struct AcceptAnyCertificate {
	algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyCertificate {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.algorithms.supported_schemes()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pkcs8_round_trips() {
		let secret = PrivateKey::from_seed(&[9; 32]);
		assert_eq!(seed_from_pkcs8_der(&pkcs8_der(&secret)), Some([9; 32]));
		assert_eq!(seed_from_pkcs8_der(&[0; 48]), None);
	}

	#[test]
	fn builds_configs() {
		TlsConfigs::new(&PrivateKey::from_seed(&[3; 32])).unwrap();
	}
}
