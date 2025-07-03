import pyshark
import re

def clean_html_content(content):
    """清理HTML内容，去除所有调试信息和格式标记"""
    # 去除ANSI颜色代码
    content = re.sub(r'\x1b\[[0-9;]*m', '', content)
    content = re.sub(r'\[\d+m\[\d+m|\[\d+m', '', content)
    
    # 去除 […] 标记
    content = re.sub(r'\s*\[…\]', '', content)
    
    # 去除多余的制表符和换行符
    content = re.sub(r'\\n', '\n', content)
    content = re.sub(r'\\t', '\t', content)
    
    # 去除行首的制表符和空格（保持HTML缩进结构）
    lines = content.split('\n')
    cleaned_lines = []
    for line in lines:
        # 去除行首的制表符，但保持基本的HTML缩进
        cleaned_line = re.sub(r'^\s*', '', line)
        if cleaned_line.strip():  # 只保留非空行
            cleaned_lines.append(cleaned_line)
    
    return '\n'.join(cleaned_lines)

def format_html(html_content):
    """简单的HTML格式化"""
    # 在主要标签前后添加换行
    html_content = re.sub(r'(<(?:html|head|body|div|header|main|footer|section|article)[^>]*>)', r'\n\1\n', html_content)
    html_content = re.sub(r'(</(?:html|head|body|div|header|main|footer|section|article)>)', r'\n\1\n', html_content)
    
    # 清理多余的空行
    html_content = re.sub(r'\n\s*\n', '\n', html_content)
    
    return html_content.strip()

# cap = pyshark.FileCapture('wiki/奥特曼.pcapng', display_filter='tcp.stream eq 8 and http2.streamid eq 1', tshark_path='D:\\else\\wireshark\\tshark.exe')
# cap = pyshark.FileCapture('wiki/尼亚加拉瀑布.pcapng', display_filter='tcp.stream eq 70 and http2.streamid eq 15', tshark_path='D:\\else\\wireshark\\tshark.exe')
cap = pyshark.FileCapture('wiki/孙策.pcapng', display_filter='tcp.stream eq 12 and http2.streamid eq 21', tshark_path='D:\\else\\wireshark\\tshark.exe')
# cap = pyshark.FileCapture('wiki/五大湖.pcapng', display_filter='tcp.stream eq 37 and http2.streamid eq 23', tshark_path='D:\\else\\wireshark\\tshark.exe')
# cap = pyshark.FileCapture('wiki/假面骑士.pcapng', display_filter='tcp.stream eq 33 and http2.streamid eq 19', tshark_path='D:\\else\\wireshark\\tshark.exe')


# 初始化变量来收集内容
extracted_html_content = ""
protocol_info = []

for pkt in cap:
    packet_info = f"\n=== Packet {pkt.number} ===\n"
    print(packet_info.strip())
    protocol_info.append(packet_info)
    
    # 检查 TCP 信息
    if hasattr(pkt, 'tcp'):
        tcp_info = f"TCP Stream: {pkt.tcp.stream}\nTCP Seq: {pkt.tcp.seq}\n"
        print(tcp_info.strip())
        protocol_info.append(tcp_info)
    
    # 检查 HTTP/2 信息
    if hasattr(pkt, 'http2'):
        http2 = pkt.http2
        http2_info = "HTTP/2 Layer found\n"
        print(http2_info.strip())
        protocol_info.append(http2_info)
        
        # 显示可用字段
        if hasattr(http2, 'field_names'):
            field_info = f"Field names: {http2.field_names}\n"
            print(field_info.strip())
            protocol_info.append(field_info)
        
        # 安全地获取字段值
        for field_name in ['stream', 'magic', 'type', 'streamid', 'length', 'flags']:
            try:
                if hasattr(http2, field_name):
                    value = getattr(http2, field_name)
                    field_info = f"  {field_name}: {value}\n"
                    print(field_info.strip())
                    protocol_info.append(field_info)
            except (AttributeError, Exception):
                pass
        
        # 使用 get_field_value 方法获取字段
        common_fields = ['http2.type', 'http2.streamid', 'http2.length', 'http2.flags', 
                        'http2.header.name', 'http2.header.value', 'http2.data']
        method_info = "\nTrying get_field_value method:\n"
        print(method_info.strip())
        protocol_info.append(method_info)
        
        for field in common_fields:
            try:
                value = http2.get_field_value(field)
                if value:
                    field_info = f"  {field}: {value}\n"
                    print(field_info.strip())
                    protocol_info.append(field_info)
                    # 如果是数据字段，收集HTML内容
                    if field == 'http2.data' and value:
                        extracted_html_content += str(value)
            except:
                pass
        
        # 获取原始层信息
        raw_layer_str = str(http2)
        
        # 检查原始层是否包含HTML内容
        if any(tag in raw_layer_str.lower() for tag in ['<html', '<div', '<body', '<head', '<li', '<ul', '<dl']):
            html_found_info = f"Found HTML content in raw layer: {len(raw_layer_str)} chars\n"
            print(html_found_info.strip())
            protocol_info.append(html_found_info)
            
            # 提取纯HTML内容
            html_start = raw_layer_str.find('<!DOCTYPE html>')
            if html_start == -1:
                html_start = raw_layer_str.find('<html')
            
            if html_start != -1:
                html_content = raw_layer_str[html_start:]
                extracted_html_content += html_content
            else:
                extracted_html_content += raw_layer_str
        
        # 显示原始层信息（截断显示以避免过长输出）
        if len(raw_layer_str) > 200:
            raw_info = f"\nRaw layer (truncated): {raw_layer_str[:200]}...\n"
        else:
            raw_info = f"\nRaw layer: {raw_layer_str}\n"
        print(raw_info.strip())
        protocol_info.append(raw_info)
        
        # 添加更详细的HTTP/2字段分析
        # 只处理DATA帧
        if hasattr(http2, 'type') and http2.type == '0':  # DATA frame
            # 处理数据帧
            if hasattr(http2, 'data'):
                data_content = str(http2.data)
                data_info = f"HTTP/2 Data: {len(data_content)} chars\n"
                print(data_info.strip())
                protocol_info.append(data_info)
                extracted_html_content += data_content

# 保存协议信息到单独文件
with open('protocol_info.txt', 'w', encoding='utf-8') as f:
    f.writelines(protocol_info)
print(f"\n✅ 已保存协议信息到 protocol_info.txt ({len(''.join(protocol_info))} 字符)")

# 保存HTML内容到单独文件
if extracted_html_content:
    # 清理HTML内容
    clean_html = clean_html_content(extracted_html_content)
    
    # 查找并提取纯HTML部分
    html_start = clean_html.find('<!DOCTYPE html>')
    if html_start == -1:
        html_start = clean_html.find('<html')
    
    if html_start != -1:
        pure_html = clean_html[html_start:]
        # 查找HTML结束位置
        html_end = pure_html.rfind('</html>')
        if html_end != -1:
            pure_html = pure_html[:html_end + 7]  # +7 for '</html>'
        
        # 进一步格式化HTML
        formatted_html = format_html(pure_html)
        
        with open('extracted_content.html', 'w', encoding='utf-8') as f:
            f.write(formatted_html)
        print(f"✅ 已保存纯HTML内容到 extracted_content.html ({len(formatted_html)} 字符)")
    else:
        # 如果没找到标准HTML，保存清理后的内容
        with open('extracted_content.html', 'w', encoding='utf-8') as f:
            f.write(clean_html)
        print(f"✅ 已保存清理后的内容到 extracted_content.html ({len(clean_html)} 字符)")
else:
    print("\n❌ 未找到HTML内容")
