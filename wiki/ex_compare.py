import pyshark
import re
import json
from datetime import datetime
from html import unescape
from bs4 import BeautifulSoup

def format_html_content(html_text):
    """格式化HTML内容，使其更易读"""
    try:
        # 解码HTML实体
        decoded_html = unescape(html_text)
        
        # 使用BeautifulSoup解析和格式化HTML
        soup = BeautifulSoup(decoded_html, 'html.parser')
        
        # 提取关键信息
        formatted_info = {
            'title': soup.title.string if soup.title else 'N/A',
            'meta_tags': [],
            'scripts': [],
            'stylesheets': [],
            'body_content_preview': '',
            'total_length': len(decoded_html),
            'formatted_html': soup.prettify()[:2000]  # 限制长度
        }
        
        # 提取meta标签
        for meta in soup.find_all('meta'):
            meta_info = {}
            for attr in ['name', 'content', 'property', 'charset']:
                if meta.get(attr):
                    meta_info[attr] = meta.get(attr)
            if meta_info:
                formatted_info['meta_tags'].append(meta_info)
        
        # 提取脚本信息
        for script in soup.find_all('script'):
            script_info = {
                'src': script.get('src', 'inline'),
                'type': script.get('type', 'text/javascript'),
                'content_length': len(script.string) if script.string else 0
            }
            formatted_info['scripts'].append(script_info)
        
        # 提取样式表信息
        for link in soup.find_all('link', rel='stylesheet'):
            formatted_info['stylesheets'].append({
                'href': link.get('href', ''),
                'type': link.get('type', 'text/css')
            })
        
        # 提取body内容预览
        if soup.body:
            body_text = soup.body.get_text(strip=True)
            formatted_info['body_content_preview'] = body_text[:500]
        
        return formatted_info
        
    except Exception as e:
        return {
            'error': f'格式化失败: {str(e)}',
            'raw_preview': html_text[:500],
            'total_length': len(html_text)
        }

def extract_raw_data(packet):
    """提取数据包的原始数据"""
    raw_data = {
        'packet_number': packet.number,
        'timestamp': str(packet.sniff_time) if hasattr(packet, 'sniff_time') else 'N/A',
        'tcp_data': None,
        'http2_data': None,
        'encrypted_data': None,
        'decrypted_data': None
    }
    
    # 提取TCP层原始数据
    if hasattr(packet, 'tcp'):
        tcp_info = {
            'stream': packet.tcp.stream if hasattr(packet.tcp, 'stream') else 'N/A',
            'seq': packet.tcp.seq if hasattr(packet.tcp, 'seq') else 'N/A',
            'payload': str(packet.tcp.payload) if hasattr(packet.tcp, 'payload') else 'N/A'
        }
        raw_data['tcp_data'] = tcp_info
    
    # 提取HTTP/2层数据
    if hasattr(packet, 'http2'):
        http2 = packet.http2
        http2_info = {
            'type': getattr(http2, 'type', 'N/A'),
            'streamid': getattr(http2, 'streamid', 'N/A'),
            'length': getattr(http2, 'length', 'N/A'),
            'flags': getattr(http2, 'flags', 'N/A'),
            'raw_layer': str(http2)  # 保留PyShark的原始解析
        }
        
        # 尝试直接提取HTTP/2数据字段的完整内容
        try:
            # 方法1：尝试获取http2.data字段
            if hasattr(http2, 'data'):
                http2_info['data_field'] = str(http2.data)
            
            # 方法2：尝试获取所有可用字段
            all_fields = []
            for field_name in http2._all_fields:
                if 'data' in field_name.lower():
                    field_value = http2.get_field_value(field_name)
                    if field_value:
                        all_fields.append({
                            'field_name': field_name,
                            'field_value': str(field_value)
                        })
            http2_info['data_fields'] = all_fields
            
        except Exception as e:
            http2_info['data_extraction_error'] = str(e)
        
        raw_data['http2_data'] = http2_info
        
        # 从TCP payload中提取HTTP/2帧的实际数据部分
        if raw_data['tcp_data'] and raw_data['tcp_data']['payload'] != 'N/A':
            tcp_payload = raw_data['tcp_data']['payload']
            # HTTP/2帧格式：9字节帧头 + 数据
            # 尝试提取帧数据部分（跳过帧头）
            try:
                # 将十六进制字符串转换为字节
                payload_bytes = bytes.fromhex(tcp_payload.replace(':', ''))
                if len(payload_bytes) > 9:  # 确保有帧头
                    frame_data = payload_bytes[9:]  # 跳过9字节帧头
                    http2_info['extracted_frame_data'] = frame_data.hex()
                    http2_info['extracted_frame_data_length'] = len(frame_data)
            except Exception as e:
                http2_info['frame_extraction_error'] = str(e)
        
        # 判断是否为加密数据还是明文数据
        # 检查提取的帧数据而不是PyShark的显示内容
        if 'extracted_frame_data' in http2_info:
            frame_data_hex = http2_info['extracted_frame_data']
            try:
                # 尝试将十六进制转换为文本
                frame_data_bytes = bytes.fromhex(frame_data_hex)
                frame_data_text = frame_data_bytes.decode('utf-8', errors='ignore')
                
                # 检查是否包含HTML标签
                if any(tag in frame_data_text.lower() for tag in ['<html', '<div', '<body', '<head', '<!doctype']):
                    # 格式化HTML内容
                    formatted_content = format_html_content(frame_data_text)
                    
                    raw_data['decrypted_data'] = {
                        'type': 'HTML_CONTENT',
                        'size': len(frame_data_hex),
                        'hex_data': frame_data_hex,
                        'text_preview': frame_data_text[:500],
                        'formatted_content': formatted_content,  # 新增格式化字段
                        'contains_html': True
                    }
                else:
                    raw_data['encrypted_data'] = {
                        'type': 'ENCRYPTED_BINARY',
                        'size': len(frame_data_hex),
                        'hex_data': frame_data_hex,
                        'contains_html': False
                    }
            except Exception as e:
                raw_data['encrypted_data'] = {
                    'type': 'ENCRYPTED_BINARY',
                    'size': len(frame_data_hex) if 'extracted_frame_data' in http2_info else 0,
                    'hex_data': frame_data_hex if 'extracted_frame_data' in http2_info else '',
                    'decode_error': str(e),
                    'contains_html': False
                }
        else:
            # 如果无法提取帧数据，回退到PyShark的解析结果
            raw_layer_str = str(http2)
            if any(tag in raw_layer_str.lower() for tag in ['<html', '<div', '<body', '<head', '<!doctype']):
                # 格式化HTML内容
                formatted_content = format_html_content(raw_layer_str)
                
                raw_data['decrypted_data'] = {
                    'type': 'HTML_CONTENT_FALLBACK',
                    'size': len(raw_layer_str),
                    'preview': raw_layer_str,
                    'formatted_content': formatted_content,  # 新增格式化字段
                    'contains_html': True
                }
            else:
                raw_data['encrypted_data'] = {
                    'type': 'ENCRYPTED_OR_BINARY_FALLBACK',
                    'size': len(raw_layer_str),
                    'preview': raw_layer_str,
                    'contains_html': False
                }
    
    return raw_data


def save_comparison_data(packet_data_list, name):
    """保存对比数据到文件"""
    # 保存为JSON格式
    with open(f'wiki/{name}_packet_comparison.json', 'w', encoding='utf-8') as f:
        json.dump(packet_data_list, f, ensure_ascii=False, indent=2)
    
    # 保存为可读的文本格式
    with open(f'wiki/{name}_packet_comparison.txt', 'w', encoding='utf-8') as f:
        f.write(f"HTTP/2 数据包密文明文对比分析\n")
        f.write(f"生成时间: {datetime.now()}\n")
        f.write("=" * 80 + "\n\n")
        
        for i, packet_data in enumerate(packet_data_list, 1):
            f.write(f"数据包 #{packet_data['packet_number']} (第{i}个)\n")
            f.write(f"时间戳: {packet_data['timestamp']}\n")
            f.write("-" * 60 + "\n")
            
            # TCP信息
            if packet_data['tcp_data']:
                tcp = packet_data['tcp_data']
                f.write(f"TCP信息:\n")
                f.write(f"  Stream: {tcp['stream']}\n")
                f.write(f"  Sequence: {tcp['seq']}\n")
                # TLS密文
                f.write(f"  Payload: {tcp['payload']}\n\n")
            
            # HTTP/2信息
            if packet_data['http2_data']:
                http2 = packet_data['http2_data']
                f.write(f"HTTP/2信息:\n")
                f.write(f"  Type: {http2['type']}\n")
                f.write(f"  Stream ID: {http2['streamid']}\n")
                f.write(f"  Length: {http2['length']}\n")
                f.write(f"  Flags: {http2['flags']}\n")
                # Http明文
                f.write(f"  Raw Layer: {http2['raw_layer']}\n\n")
                
                # 添加提取的帧数据信息
                if 'extracted_frame_data' in http2:
                    f.write(f"  提取的帧数据长度: {http2['extracted_frame_data_length']} 字节\n")
                    f.write(f"  提取的帧数据(十六进制): {http2['extracted_frame_data'][:100]}...\n\n")
            
            # 加密数据
            if packet_data['encrypted_data']:
                enc = packet_data['encrypted_data']
                f.write(f"🔒 加密数据:\n")
                f.write(f"  类型: {enc['type']}\n")
                f.write(f"  大小: {enc['size']} 字符\n")
                
                # 根据不同的字段结构选择显示内容
                if 'hex_data' in enc:
                    f.write(f"  十六进制数据: {enc['hex_data']}\n")
                elif 'preview' in enc:
                    f.write(f"  预览内容: {enc['preview']}\n")
                
                if 'decode_error' in enc:
                    f.write(f"  解码错误: {enc['decode_error']}\n")
                f.write("\n")
            
            # 明文数据
            if packet_data['decrypted_data']:
                dec = packet_data['decrypted_data']
                f.write(f"🔓 明文数据:\n")
                f.write(f"  类型: {dec['type']}\n")
                f.write(f"  大小: {dec['size']} 字符\n")
                f.write(f"  包含HTML: {dec['contains_html']}\n")
                
                # 根据不同的字段结构选择显示内容
                if 'text_preview' in dec:
                    f.write(f"  文本预览: {dec['text_preview']}\n")
                    if 'hex_data' in dec:
                        f.write(f"  十六进制数据: {dec['hex_data']}\n")
                elif 'preview' in dec:
                    f.write(f"  预览内容: {dec['preview']}\n")
                f.write("\n")
            
            f.write("=" * 80 + "\n\n")

def main():
    print("开始分析HTTP/2数据包的密文和明文数据...")
    
    name_package_dict = {
        "奥特曼": "tcp.stream eq 8 and http2.streamid eq 1",
        "假面骑士": "tcp.stream eq 33 and http2.streamid eq 19",
        "尼亚加拉瀑布": "tcp.stream eq 70 and http2.streamid eq 15",
        "孙策": "tcp.stream eq 12 and http2.streamid eq 21",
        "五大湖": "tcp.stream eq 37 and http2.streamid eq 23",
    }

    for name, filter in name_package_dict.items():
        cap = pyshark.FileCapture(f'wiki/{name}.pcapng', 
            display_filter=filter, 
            tshark_path='D:\\else\\wireshark\\tshark.exe'
            )
        packet_data_list = []
        encrypted_count = 0
        decrypted_count = 0
        
        for pkt in cap:
            print(f"处理数据包 #{pkt.number}...")
            
            # 提取数据包信息
            packet_data = extract_raw_data(pkt)
            packet_data_list.append(packet_data)
            
            # 统计加密和明文数据包
            if packet_data['encrypted_data']:
                encrypted_count += 1
                print(f"  🔒 发现加密数据 (大小: {packet_data['encrypted_data']['size']} 字符)")
            
            if packet_data['decrypted_data']:
                decrypted_count += 1
                print(f"  🔓 发现明文数据 (大小: {packet_data['decrypted_data']['size']} 字符)")
        
        # 保存对比数据
        save_comparison_data(packet_data_list, name)
        
        # 输出统计信息
        print(f"\n📊 分析完成!")
        print(f"总数据包数: {len(packet_data_list)}")
        print(f"加密数据包: {encrypted_count}")
        print(f"明文数据包: {decrypted_count}")
        print(f"\n📁 输出文件:")
        print(f"  - {name}_packet_comparison.json (JSON格式)")
        print(f"  - {name}_packet_comparison.txt (可读格式)")

if __name__ == "__main__":
    main()