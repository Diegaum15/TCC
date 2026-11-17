// Módulo de transporte seguro com Autenticação Mútua TLS (mTLS)
//
// Encapsula a configuração do `rustls` para garantir que tanto o servidor
// quanto o cliente apresentem certificados X.509 válidos assinados pela
// mesma Autoridade Certificadora (CA) privada do experimento

use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    ServerConfig, ServerConnection, StreamOwned,
};

// Lê e decodifica um ou mais certificados X.509 em formato PEM para DER.
fn load_certificates(
    // Caminho para o arquivo PEM contendo os certificados
    path: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {

    // Abre o arquivo de certificados e cria um leitor bufferizado
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Lê todos os certificados PEM do arquivo e converte para DER
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    // Verifica se algum certificado foi carregado
    if certificates.is_empty() {
        return Err(format!("Nenhum certificado encontrado em {path}").into());
    }

    Ok(certificates)
}

// Lê e decodifica a chave privada (PKCS#8 / SEC1) em formato PEM para DER.
fn load_private_key(
    // Caminho para o arquivo PEM contendo a chave privada
    path: &str,
) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    // Abre o arquivo de chave privada e cria um leitor bufferizado
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Lê a primeira chave privada PEM do arquivo e converte para DER
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| {
            // Retorna um erro se nenhuma chave privada for encontrada
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Nenhuma chave privada encontrada em {path}"),
            )
        })?;

    Ok(key)
}

// Constrói um repositório de confiança (`RootCertStore`) contendo o certificado
// da Autoridade Certificadora (CA) responsável por emitir as identidades dos nós.
fn load_root_store(path: &str) -> Result<RootCertStore, Box<dyn Error>> {
    // Carrega os certificados da CA a partir do arquivo PEM
    let certificates = load_certificates(path)?;
    let mut roots = RootCertStore::empty();

    // Adiciona cada certificado da CA ao repositório de confiança
    for certificate in certificates {
        roots.add(certificate)?;
    }

    Ok(roots)
}

// Cria a configuração TLS para os nós servidores (`frost-node-*`).
// Utiliza `WebPkiClientVerifier` para exigir obrigatoriamente que qualquer
// cliente (coordenador ou outro nó na Round 2) apresente um certificado
// válido assinado pela CA antes de estabelecer a sessão (mTLS).
pub fn server_config(
    certificate_path: &str,
    private_key_path: &str,
    ca_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn Error>> {
    // Carrega os certificados do servidor, a chave privada e o repositório de confiança da CA
    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let roots = load_root_store(ca_path)?;

    // Cria um verificador de cliente que valida os certificados apresentados
    let client_verifier =
        WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    // Constrói a configuração do servidor TLS com autenticação mútua
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificates, private_key)?;

    Ok(Arc::new(config))
}

// Cria a configuração TLS para clientes (`frost-coordinator` e nós na Round 2).
// Configura a raiz de confiança (`with_root_certificates`) para validar o
// servidor de destino e anexa o certificado de identidade local
// (`with_client_auth_cert`) para autenticação mútua.
pub fn client_config(
    certificate_path: &str,
    private_key_path: &str,
    ca_path: &str,
) -> Result<Arc<ClientConfig>, Box<dyn Error>> {
    // Carrega os certificados do cliente, a chave privada e o repositório de confiança da CA
    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let roots = load_root_store(ca_path)?;

    // Constrói a configuração do cliente TLS com autenticação mútua
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)?;

    Ok(Arc::new(config))
}

// Envolve um socket TCP recém-aceito (`TcpStream`) em uma sessão TLS de servidor,
// realizando o handshake criptográfico e a verificação do certificado do cliente.
pub fn accept_tls(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<StreamOwned<ServerConnection, TcpStream>, Box<dyn Error>> {
    // Cria uma nova conexão TLS de servidor com a configuração fornecida
    let connection = ServerConnection::new(config)?;
    Ok(StreamOwned::new(connection, stream))
}

// Estabelece uma conexão TCP com `address`, valida o Subject Alternative Name (SAN)
// contra `server_name` e conclui o handshake mTLS de cliente.
pub fn connect_tls(
    address: &str,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    // Conecta-se ao servidor remoto via TCP
    let stream = TcpStream::connect(address)?;

    //  Valida o nome do servidor contra o certificado apresentado durante o handshake
    let server_name = ServerName::try_from(server_name.to_owned())?;
    let connection = ClientConnection::new(config, server_name)?;

    Ok(StreamOwned::new(connection, stream))
}