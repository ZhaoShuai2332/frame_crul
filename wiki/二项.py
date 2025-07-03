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
            'formatted_html': soup.prettify()
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
            formatted_info['body_content_preview'] = body_text
        
        return formatted_info
        
    except Exception as e:
        return {
            'error': f'格式化失败: {str(e)}',
            'raw_preview': html_text,
            'total_length': len(html_text)
        }

def extract_raw_data(packet):
    """从数据包中提取原始数据"""
    raw_data = {
        'packet_number': packet.number,
        'timestamp': str(packet.sniff_time),  # 转换为字符串
        # 移除packet_obj，避免序列化问题
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
    
    # 提取TLS层数据（用于密文）
    tls_data = None
    if hasattr(packet, 'tls'):
        try:
            if hasattr(packet.tls, 'app_data'):
                tls_data = str(packet.tls.app_data)
            elif hasattr(packet.tls, 'record'):
                tls_data = str(packet.tls.record)
        except:
            pass
    raw_data['tls_data'] = tls_data
    
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
                
                # 更全面的明文判断逻辑
                is_plaintext = False
                
                # 1. 检查是否包含可打印的ASCII字符比例
                printable_chars = sum(1 for c in frame_data_text if c.isprintable())
                printable_ratio = printable_chars / len(frame_data_text) if len(frame_data_text) > 0 else 0
                
                # 2. 检查是否包含常见的文本模式
                text_patterns = [
                    '<html', '<div', '<body', '<head', '<!doctype',  # HTML标签
                    'http://', 'https://',  # URL
                    'content-type', 'user-agent', 'accept',  # HTTP头
                    '{', '}', '[', ']',  # JSON格式
                    'var ', 'function', 'return',  # JavaScript
                    'charset=', 'encoding=',  # 编码信息
                ]
                
                has_text_patterns = any(pattern in frame_data_text.lower() for pattern in text_patterns)
                
                # 3. 检查字节熵（简单实现）
                byte_counts = {}
                for byte_val in frame_data_bytes:
                    byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
                
                # 计算简单的字节分布均匀度
                unique_bytes = len(byte_counts)
                total_bytes = len(frame_data_bytes)
                byte_diversity = unique_bytes / total_bytes if total_bytes > 0 else 0
                
                # 判断逻辑：
                # - 可打印字符比例 > 70% 且包含文本模式，或
                # - 可打印字符比例 > 90%，或
                # - 字节多样性 < 0.8（表示重复模式较多，可能是文本）
                if (printable_ratio > 0.7 and has_text_patterns) or printable_ratio > 0.9 or byte_diversity < 0.8:
                    is_plaintext = True
                
                if is_plaintext:
                    # 格式化内容（如果是HTML）
                    formatted_content = None
                    if any(tag in frame_data_text.lower() for tag in ['<html', '<div', '<body', '<head', '<!doctype']):
                        formatted_content = format_html_content(frame_data_text)
                    
                    raw_data['decrypted_data'] = {
                        'type': 'PLAINTEXT_CONTENT',
                        'size': len(frame_data_hex),
                        'hex_data': frame_data_hex,
                        'text_preview': frame_data_text,
                        'formatted_content': formatted_content,
                        'contains_html': any(tag in frame_data_text.lower() for tag in ['<html', '<div', '<body', '<head', '<!doctype']),
                        'printable_ratio': printable_ratio,
                        'has_text_patterns': has_text_patterns,
                        'byte_diversity': byte_diversity
                    }
                else:
                    raw_data['encrypted_data'] = {
                        'type': 'ENCRYPTED_BINARY',
                        'size': len(frame_data_hex),
                        'hex_data': frame_data_hex,
                        'contains_html': False,
                        'printable_ratio': printable_ratio,
                        'has_text_patterns': has_text_patterns,
                        'byte_diversity': byte_diversity
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
            
            # 对PyShark解析结果也应用相同的判断逻辑
            printable_chars = sum(1 for c in raw_layer_str if c.isprintable())
            printable_ratio = printable_chars / len(raw_layer_str) if len(raw_layer_str) > 0 else 0
            
            text_patterns = [
                '<html', '<div', '<body', '<head', '<!doctype',
                'http://', 'https://', 'content-type', 'user-agent', 'accept',
                '{', '}', '[', ']', 'var ', 'function', 'return',
                'charset=', 'encoding='
            ]
            has_text_patterns = any(pattern in raw_layer_str.lower() for pattern in text_patterns)
            
            if printable_ratio > 0.7 and has_text_patterns:
                # 格式化HTML内容
                formatted_content = None
                if any(tag in raw_layer_str.lower() for tag in ['<html', '<div', '<body', '<head', '<!doctype']):
                    formatted_content = format_html_content(raw_layer_str)
                
                raw_data['decrypted_data'] = {
                    'type': 'PLAINTEXT_CONTENT_FALLBACK',
                    'size': len(raw_layer_str),
                    'preview': raw_layer_str,
                    'formatted_content': formatted_content,
                    'contains_html': any(tag in raw_layer_str.lower() for tag in ['<html', '<div', '<body', '<head', '<!doctype']),
                    'printable_ratio': printable_ratio,
                    'has_text_patterns': has_text_patterns,
                }
            else:
                raw_data['encrypted_data'] = {
                    'type': 'ENCRYPTED_OR_BINARY_FALLBACK',
                    'size': len(raw_layer_str),
                    'preview': raw_layer_str,
                    'contains_html': False,
                    'printable_ratio': printable_ratio,
                    'has_text_patterns': has_text_patterns
                }
    
    return raw_data


def save_comparison_data(packet_data_list, name):
    """保存对比数据到文件"""
    # 保存为JSON格式
    with open(f'wiki/{name}_packet_comparison.json', 'w', encoding='utf-8') as f:
        json.dump(packet_data_list, f, ensure_ascii=False, indent=2)
    
    # 保存为可读的文本格式
    with open(f'wiki/{name}_packet_comparison.txt', 'w', encoding='utf-8') as f:
        f.write(f"HTTP/2 数据包密文明文对比分析（简化版）\n")
        f.write(f"生成时间: {datetime.now()}\n")
        f.write("=" * 80 + "\n\n")
        
        for i, packet_data in enumerate(packet_data_list, 1):
            f.write(f"数据包 #{packet_data['packet_number']} (第{i}个)\n")
            f.write(f"时间戳: {packet_data['timestamp']}\n")
            f.write("-" * 60 + "\n")
            
            # HTTP/2基本信息
            if packet_data['http2_data']:
                http2 = packet_data['http2_data']
                f.write(f"Type: {http2['type']}\n")
                f.write(f"Stream ID: {http2['streamid']}\n")
                f.write(f"Length: {http2['length']}\n")
                f.write(f"Flags: {http2['flags']}\n")
                f.write("\n")
            
            # 四行关键数据
            # 1. 密文数据（TLS层的Application Data）
            tls_data = packet_data.get('tls_data', 'N/A')
            if tls_data == 'N/A' or not tls_data:
                # 如果没有TLS数据，使用TCP载荷作为密文
                if packet_data['tcp_data'] and packet_data['tcp_data']['payload'] != 'N/A':
                    tls_data = packet_data['tcp_data']['payload']
            f.write(f"密文: {tls_data}\n")
            
            # 2. 原始明文（wireshark抓到的原始数据包内容）
            if packet_data['tcp_data'] and packet_data['tcp_data']['payload'] != 'N/A':
                f.write(f"原始明文: {packet_data['tcp_data']['payload']}\n")
            else:
                f.write(f"原始明文: N/A\n")
            
            # 3. 解码后明文（HTTP/2层的Data帧内容）
            # http2_data = "N/A"
            # if packet_data['decrypted_data']:
            #     if 'text_preview' in packet_data['decrypted_data']:
            #         http2_data = packet_data['decrypted_data']['text_preview']
            #     elif 'preview' in packet_data['decrypted_data']:
            #         http2_data = packet_data['decrypted_data']['preview']
            # elif packet_data['http2_data']:
            #     # 使用HTTP/2层的原始解析结果
            #     http2_data = packet_data['http2_data']['raw_layer']
            # 
            # f.write(f"解码后明文: {http2_data}\n")
            
            # 4. 人肉眼可读明文（真正的可视化内容）
            readable_text = "N/A"
            if packet_data['http2_data']:
                http2_info = packet_data['http2_data']
                
                # 直接使用raw_layer的内容作为可视化明文
                # 这样可以显示完整的HTTP/2解析信息，类似于txt文件中的格式
                raw_layer = http2_info.get('raw_layer', '')
                
                if raw_layer:
                    # 保持原始的raw_layer格式，这包含了完整的HTTP/2帧解析信息
                    # 包括帧类型、标志位、头部信息、cookie等详细内容
                    readable_text = raw_layer
                else:
                    # 如果没有raw_layer，回退到原来的逻辑
                    readable_parts = []
                    
                    # 添加帧类型的可读描述
                    frame_type = http2_info.get('type', 'Unknown')
                    frame_type_desc = {
                        '0': 'DATA帧(数据传输)',
                        '1': 'HEADERS帧(HTTP头)',
                        '2': 'PRIORITY帧(优先级)',
                        '3': 'RST_STREAM帧(重置流)',
                        '4': 'SETTINGS帧(设置)',
                        '5': 'PUSH_PROMISE帧(推送承诺)',
                        '6': 'PING帧(心跳)',
                        '7': 'GOAWAY帧(关闭连接)',
                        '8': 'WINDOW_UPDATE帧(窗口更新)',
                        '9': 'CONTINUATION帧(头部延续)'
                    }.get(str(frame_type), f'未知帧类型({frame_type})')
                    
                    readable_parts.append(f"帧类型: {frame_type_desc}")
                    
                    # 根据帧类型提取相应的可读信息
                    if str(frame_type) == '1':  # HEADERS帧
                        readable_parts.append("包含HTTP请求/响应头信息")
                    elif str(frame_type) == '0':  # DATA帧
                        if packet_data['decrypted_data']:
                            dec_data = packet_data['decrypted_data']
                            if dec_data.get('contains_html', False):
                                readable_parts.append("内容: HTML网页数据")
                            elif 'text_preview' in dec_data:
                                text = dec_data['text_preview']
                                if text.strip().startswith('{') and text.strip().endswith('}'):
                                    readable_parts.append("内容: JSON数据")
                                elif 'function' in text or 'var ' in text:
                                    readable_parts.append("内容: JavaScript代码")
                                else:
                                    readable_parts.append("内容: 文本数据")
                        else:
                            readable_parts.append("内容: 二进制数据")
                    elif str(frame_type) == '4':  # SETTINGS帧
                        readable_parts.append("内容: HTTP/2连接设置参数")
                    elif str(frame_type) == '6':  # PING帧
                        readable_parts.append("内容: 连接保活心跳")
                    elif str(frame_type) == '8':  # WINDOW_UPDATE帧
                        readable_parts.append("内容: 流量控制窗口更新")
                    
                    # 添加数据大小信息
                    if 'length' in http2_info:
                        size = int(http2_info['length'])
                        if size > 1024:
                            size_desc = f"{size/1024:.1f}KB"
                        else:
                            size_desc = f"{size}字节"
                        readable_parts.append(f"大小: {size_desc}")
                    
                    # 添加流ID信息
                    if 'streamid' in http2_info:
                        readable_parts.append(f"流ID: {http2_info['streamid']}")
                    
                    if readable_parts:
                        readable_text = ' | '.join(readable_parts)
                    else:
                        readable_text = "[无法解析的HTTP/2帧数据]"
            else:
                readable_text = "[非HTTP/2数据包]"
            
            f.write(f"可视化明文: {readable_text}\n")
            
            f.write("=" * 80 + "\n\n")

def main():
    print("开始分析HTTP/2数据包的密文和明文数据（改进版）...")
    
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
                enc = packet_data['encrypted_data']
                print(f"  🔒 发现加密数据 (大小: {enc['size']} 字符)")
                if 'printable_ratio' in enc:
                    print(f"      可打印字符比例: {enc['printable_ratio']:.2%}")
            
            if packet_data['decrypted_data']:
                decrypted_count += 1
                dec = packet_data['decrypted_data']
                print(f"  🔓 发现明文数据 (大小: {dec['size']} 字符)")
                if 'printable_ratio' in dec:
                    print(f"      可打印字符比例: {dec['printable_ratio']:.2%}")
        
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