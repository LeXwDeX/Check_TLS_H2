import socket
import ssl
import http.client
import time
import argparse

#### 功能描述 ####
# 本脚本用于测试域名的TLSv1.3和H2支持情况，并可选地检查OCSP Stapling支持情况。
# 脚本使用Python3编写，依赖于ssl、http.client、socket、argparse等模块。   
#### 使用方法 ####
# python3 Check_TLS_H2.py www.example.com --check-ocsp

def get_server_names(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.connect((domain, 443))
    cert = conn.getpeercert()
    server_names = cert.get('subjectAltName', ())
    conn.close()
    return [name[1] for name in server_names if name[0].lower() == 'dns']

def test_tls_h2_support(server_name, check_ocsp):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/1.1'])
    
    try:
        start_time = time.time()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server_name)
        conn.connect((server_name, 443))
        end_time = time.time()
        protocol = conn.selected_alpn_protocol()
        tls_version = conn.version()
        has_ocsp_stapling = False
        if check_ocsp:
            cert = conn.getpeercert(binary_form=True)
            has_ocsp_stapling = b'OCSP' in cert
        if protocol == 'h2' and tls_version == 'TLSv1.3' and (not check_ocsp or has_ocsp_stapling):
            return True, end_time - start_time
        else:
            return False, None
    except Exception as e:
        print(f"Error connecting to {server_name}: {e}")
        return False, None
    finally:
        conn.close()

def test_no_redirect(server_name):
    conn = http.client.HTTPSConnection(server_name, context=ssl.create_default_context())
    conn.request("HEAD", "/", headers={"Connection": "close"})
    response = conn.getresponse()
    conn.close()
    return response.status not in (301, 302, 303, 307, 308)

def main(domain, check_ocsp):
    print(f"Getting server names for {domain}")
    server_names = get_server_names(domain)
    print(f"Server names: {server_names}")
    
    supported_server_names = []
    for server_name in server_names:
        print(f"Testing {server_name} for TLSv1.3 and H2 support...")
        tls_h2_support, latency = test_tls_h2_support(server_name, check_ocsp)
        if tls_h2_support:
            print(f"Testing {server_name} for no redirect...")
            if test_no_redirect(server_name):
                supported_server_names.append((server_name, latency))

    supported_server_names.sort(key=lambda x: x[1])
    print(f"Supported server names sorted by latency: {supported_server_names}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test server names for TLSv1.3 and H2 support.')
    parser.add_argument('domain', type=str, help='The domain to test.')
    parser.add_argument('--check-ocsp', action='store_true', help='Check for OCSP Stapling support.')
    args = parser.parse_args()
    
    main(args.domain, args.check_ocsp)