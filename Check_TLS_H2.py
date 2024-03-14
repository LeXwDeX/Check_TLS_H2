import socket
import ssl
import http.client
import time
import argparse

#### 功能描述 ####
# TLS 1.3以及X25519证书检查
# 脚本使用Python3编写，依赖于ssl、http.client、socket、argparse等模块。   
#### 使用方法 ####
# python3 Check_TLS_H2.py www.example.com --check-ocsp

import socket
import ssl
import argparse

def get_server_names(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.connect((domain, 443))
    cert = conn.getpeercert()
    server_names = cert.get('subjectAltName', ())
    conn.close()
    return [name[1] for name in server_names if name[0].lower() == 'dns']

def test_tls_x25519_support(server_name):
    context = ssl.create_default_context()
    context.set_ciphers('ECDHE+AESGCM')
    
    try:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server_name)
        conn.connect((server_name, 443))
        tls_version = conn.version()
        cipher = conn.cipher()
        if tls_version == 'TLSv1.3' and cipher[0] == 'TLS_AES_256_GCM_SHA384' and cipher[1] == 'X25519':
            return True
        else:
            return False
    except Exception as e:
        print(f"Error connecting to {server_name}: {e}")
        return False
    finally:
        conn.close()

def main(domain):
    print(f"Getting server names for {domain}")
    server_names = get_server_names(domain)
    print(f"Server names: {server_names}")
    
    supported_server_names = []
    for server_name in server_names:
        print(f"Testing {server_name} for TLSv1.3 and X25519 support...")
        tls_x25519_support = test_tls_x25519_support(server_name)
        if tls_x25519_support:
            supported_server_names.append(server_name)

    print(f"Supported server names with TLSv1.3 and X25519: {supported_server_names}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test server names for TLSv1.3 and X25519 support.')
    parser.add_argument('domain', type=str, help='The domain to test.')
    args = parser.parse_args()
    
    main(args.domain)
