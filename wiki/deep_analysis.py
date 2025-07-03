import json
import pyshark
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import binascii
import re
from datetime import datetime
import os
from scipy import stats
import base64

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 配置信息
name_package_dict = {
    "奥特曼": "(tcp.stream eq 8 and http2) && (ip.src == 198.18.0.7)",
    "假面骑士": "(tcp.stream eq 33 and http2) && (ip.src == 198.18.0.21)",
    "尼亚加拉瀑布": "(tcp.stream eq 70 and http2) && (ip.src == 198.18.0.14)",
    "孙策": "(tcp.stream eq 12 and http2) && (ip.src == 198.18.0.14)",
    "五大湖": "(tcp.stream eq 37 and http2) && (ip.src == 198.18.0.14)",
}

tshark_path = "D:\\else\\wireshark\\tshark.exe"

# 在tshark_path配置后添加以下函数
def safe_int_convert(value, default=0):
    """安全地将各种类型的值转换为整数"""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        # 处理十六进制字符串
        if value.startswith('0x'):
            try:
                return int(value, 16)
            except ValueError:
                return default
        # 处理普通字符串
        try:
            return int(value)
        except ValueError:
            return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def calculate_entropy(data):
    """计算数据的熵值"""
    if not data:
        return 0
    
    # 转换为字节
    if isinstance(data, str):
        try:
            # 尝试解析十六进制
            if data.startswith('0x'):
                data = data[2:]
            data = bytes.fromhex(data.replace(':', '').replace(' ', ''))
        except:
            data = data.encode('utf-8')
    
    # 计算字节频率
    byte_counts = Counter(data)
    total_bytes = len(data)
    
    # 计算熵
    entropy = 0
    for count in byte_counts.values():
        probability = count / total_bytes
        if probability > 0:
            entropy -= probability * np.log2(probability)
    
    return entropy

def analyze_padding(data):
    """分析数据的填充情况"""
    if not data:
        return {'padding_detected': False, 'padding_bytes': 0, 'padding_pattern': None}
    
    # 转换为字节
    if isinstance(data, str):
        try:
            if data.startswith('0x'):
                data = data[2:]
            data = bytes.fromhex(data.replace(':', '').replace(' ', ''))
        except:
            data = data.encode('utf-8')
    
    # 检查常见的填充模式
    padding_info = {
        'padding_detected': False,
        'padding_bytes': 0,
        'padding_pattern': None,
        'padding_type': None
    }
    
    if len(data) == 0:
        return padding_info
    
    # PKCS#7 填充检测
    last_byte = data[-1]
    if last_byte <= 16:  # PKCS#7 最大填充长度
        potential_padding = data[-last_byte:]
        if all(b == last_byte for b in potential_padding):
            padding_info['padding_detected'] = True
            padding_info['padding_bytes'] = last_byte
            padding_info['padding_pattern'] = f"0x{last_byte:02x}"
            padding_info['padding_type'] = 'PKCS#7'
    
    # 零填充检测
    trailing_zeros = 0
    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0:
            trailing_zeros += 1
        else:
            break
    
    if trailing_zeros > 0 and not padding_info['padding_detected']:
        padding_info['padding_detected'] = True
        padding_info['padding_bytes'] = trailing_zeros
        padding_info['padding_pattern'] = "0x00"
        padding_info['padding_type'] = 'Zero Padding'
    
    return padding_info

def extract_text_content(data):
    """提取数据中的文本内容"""
    text_content = {
        'readable_text': '',
        'text_ratio': 0,
        'contains_html': False,
        'contains_json': False,
        'contains_image_data': False
    }
    
    if not data:
        return text_content
    
    # 转换为字节
    if isinstance(data, str):
        try:
            if data.startswith('0x'):
                data = data[2:]
            data = bytes.fromhex(data.replace(':', '').replace(' ', ''))
        except:
            data = data.encode('utf-8')
    
    # 尝试解码为文本
    try:
        text = data.decode('utf-8', errors='ignore')
        # 计算可读字符比例
        printable_chars = sum(1 for c in text if c.isprintable())
        text_content['text_ratio'] = printable_chars / len(text) if text else 0
        
        # 提取可读文本
        readable_text = ''.join(c for c in text if c.isprintable())
        text_content['readable_text'] = readable_text[:500]  # 限制长度
        
        # 检测内容类型
        text_lower = readable_text.lower()
        text_content['contains_html'] = '<html' in text_lower or '<!doctype' in text_lower
        text_content['contains_json'] = ('{' in text and '}' in text) or ('[' in text and ']' in text)
        
        # 检测图片数据特征
        image_signatures = [b'\xff\xd8\xff', b'\x89PNG', b'GIF8', b'RIFF']
        text_content['contains_image_data'] = any(sig in data for sig in image_signatures)
        
    except Exception as e:
        pass
    
    return text_content

def analyze_fragmentation(packets):
    """分析数据分片情况"""
    fragmentation_info = {
        'total_fragments': len(packets),
        'fragment_sizes': [],
        'size_variance': 0,
        'reassembly_order': [],
        'gaps_detected': False
    }
    
    for packet in packets:
        if hasattr(packet, 'tcp'):
            seq_num = safe_int_convert(packet.tcp.seq)
            payload_len = safe_int_convert(getattr(packet.tcp, 'len', 0))
            fragmentation_info['fragment_sizes'].append(payload_len)
            fragmentation_info['reassembly_order'].append(seq_num)
    
    if fragmentation_info['fragment_sizes']:
        fragmentation_info['size_variance'] = np.var(fragmentation_info['fragment_sizes'])
    
    # 检测序列号间隙
    if len(fragmentation_info['reassembly_order']) > 1:
        sorted_seqs = sorted(fragmentation_info['reassembly_order'])
        for i in range(1, len(sorted_seqs)):
            if sorted_seqs[i] - sorted_seqs[i-1] > max(fragmentation_info['fragment_sizes']):
                fragmentation_info['gaps_detected'] = True
                break
    
    return fragmentation_info

def deep_packet_analysis(cap_file, target_name):
    """深度数据包分析"""
    # 获取对应的tshark过滤器
    display_filter = name_package_dict.get(target_name, "")
    print(f"使用过滤器: {display_filter}")
    
    # 使用tshark路径和过滤器
    cap = pyshark.FileCapture(cap_file, tshark_path=tshark_path, display_filter=display_filter)
    analysis_results = {
        'timestamp': datetime.now().isoformat(),
        'total_packets': 0,
        'detailed_analysis': [],
        'encryption_analysis': {
            'entropy_comparison': [],
            'length_expansion': [],
            'padding_analysis': [],
            'fragmentation_patterns': []
        },
        'content_analysis': {
            'text_extraction': [],
            'data_types': Counter(),
            'compression_indicators': []
        }
    }
    
    packets_by_stream = {}
    
    for packet in cap:
        analysis_results['total_packets'] += 1
        
        packet_analysis = {
            'packet_number': safe_int_convert(packet.number),
            'timestamp': str(packet.sniff_time),
            'layers': {}
        }
        
        # 分析各层数据
        for layer in packet.layers:
            layer_name = layer.layer_name
            layer_analysis = {'raw_data': None, 'decoded_data': None}
            
            if layer_name == 'tcp':
                tcp_data = {
                    'sequence_number': safe_int_convert(getattr(layer, 'seq', 0)),
                    'payload_length': safe_int_convert(getattr(layer, 'len', 0)),
                    'flags': str(layer.flags_str) if hasattr(layer, 'flags_str') else '',
                    'window_size': safe_int_convert(getattr(layer, 'window_size_value', 0))
                }
                
                # 提取TCP载荷
                if hasattr(layer, 'payload'):
                    tcp_data['payload_hex'] = str(layer.payload)
                    tcp_data['payload_entropy'] = calculate_entropy(str(layer.payload))
                
                layer_analysis['decoded_data'] = tcp_data
                
            elif layer_name == 'tls':
                tls_data = {
                    'record_type': safe_int_convert(getattr(layer, 'record_content_type', 0)),
                    'version': str(layer.record_version) if hasattr(layer, 'record_version') else '',
                    'encrypted_length': safe_int_convert(getattr(layer, 'record_length', 0))
                }
                
                # 提取加密数据
                if hasattr(layer, 'app_data'):
                    encrypted_data = str(layer.app_data)
                    tls_data['encrypted_data_hex'] = encrypted_data
                    tls_data['encrypted_entropy'] = calculate_entropy(encrypted_data)
                    tls_data['padding_analysis'] = analyze_padding(encrypted_data)
                
                layer_analysis['decoded_data'] = tls_data
                
            elif layer_name == 'http2':
                http2_data = {
                    'stream_id': safe_int_convert(getattr(layer, 'streamid', 0)),
                    'frame_type': safe_int_convert(getattr(layer, 'type', 0)),
                    'frame_length': safe_int_convert(getattr(layer, 'length', 0)),
                    'flags': safe_int_convert(getattr(layer, 'flags', 0))
                }
                
                # 提取HTTP2数据
                if hasattr(layer, 'data'):
                    plaintext_data = str(layer.data)
                    http2_data['plaintext_hex'] = plaintext_data
                    http2_data['plaintext_entropy'] = calculate_entropy(plaintext_data)
                    http2_data['text_content'] = extract_text_content(plaintext_data)
                    http2_data['padding_analysis'] = analyze_padding(plaintext_data)
                
                # 提取头部信息
                headers = {}
                for field_name in layer.field_names:
                    if field_name.startswith('headers_'):
                        header_name = field_name.replace('headers_', '')
                        headers[header_name] = str(getattr(layer, field_name))
                
                http2_data['headers'] = headers
                layer_analysis['decoded_data'] = http2_data
            
            packet_analysis['layers'][layer_name] = layer_analysis
        
        # 进行密文明文对比分析
        if 'tls' in packet_analysis['layers'] and 'http2' in packet_analysis['layers']:
            tls_layer = packet_analysis['layers']['tls']['decoded_data']
            http2_layer = packet_analysis['layers']['http2']['decoded_data']
            
            comparison = {
                'packet_number': packet_analysis['packet_number'],
                'plaintext_length': http2_layer.get('frame_length', 0),
                'ciphertext_length': tls_layer.get('encrypted_length', 0),
                'length_expansion_ratio': 0,
                'entropy_difference': 0,
                'compression_detected': False
            }
            
            if comparison['plaintext_length'] > 0:
                comparison['length_expansion_ratio'] = comparison['ciphertext_length'] / comparison['plaintext_length']
            
            # 熵值对比
            plaintext_entropy = http2_layer.get('plaintext_entropy', 0)
            ciphertext_entropy = tls_layer.get('encrypted_entropy', 0)
            comparison['entropy_difference'] = ciphertext_entropy - plaintext_entropy
            
            # 压缩检测
            if comparison['length_expansion_ratio'] < 1.0:
                comparison['compression_detected'] = True
            
            analysis_results['encryption_analysis']['entropy_comparison'].append(comparison)
        
        analysis_results['detailed_analysis'].append(packet_analysis)
        
        # 按流分组
        if 'http2' in packet_analysis['layers']:
            stream_id = packet_analysis['layers']['http2']['decoded_data'].get('stream_id', 0)
            if stream_id not in packets_by_stream:
                packets_by_stream[stream_id] = []
            packets_by_stream[stream_id].append(packet)
    
    # 分析分片模式
    for stream_id, stream_packets in packets_by_stream.items():
        if len(stream_packets) > 1:
            frag_analysis = analyze_fragmentation(stream_packets)
            frag_analysis['stream_id'] = stream_id
            analysis_results['encryption_analysis']['fragmentation_patterns'].append(frag_analysis)
    
    cap.close()
    return analysis_results

def create_deep_analysis_charts(name, analysis_data, output_dir):
    """创建优化的深度分析图表"""
    fig = plt.figure(figsize=(16, 12))
    
    # 1. 熵值对比分析 - 核心加密分析
    ax1 = plt.subplot(2, 3, 1)
    entropy_data = analysis_data['encryption_analysis']['entropy_comparison']
    if entropy_data:
        packets = [d['packet_number'] for d in entropy_data]
        plaintext_entropies = []
        ciphertext_entropies = []
        
        # 在create_deep_analysis_charts函数中
        for packet_data in analysis_data['detailed_analysis']:
            if 'tcp' in packet_data['layers'] and 'tls' in packet_data['layers']:
                tcp_entropy = packet_data['layers']['tcp']['decoded_data'].get('payload_entropy', 0)
                tls_entropy = packet_data['layers']['tls']['decoded_data'].get('encrypted_entropy', 0)
                plaintext_entropies.append(tcp_entropy)  # 使用TCP载荷熵值
                ciphertext_entropies.append(tls_entropy)
        
        if plaintext_entropies and ciphertext_entropies:
            x = np.arange(len(packets))
            width = 0.35
            ax1.bar(x - width/2, plaintext_entropies, width, label='明文熵值', alpha=0.8, color='lightblue')
            ax1.bar(x + width/2, ciphertext_entropies, width, label='密文熵值', alpha=0.8, color='lightcoral')
            ax1.set_title('明文vs密文熵值对比', fontsize=12, fontweight='bold')
            ax1.set_xlabel('数据包')
            ax1.set_ylabel('熵值')
            ax1.legend()
            ax1.set_xticks(x)
            ax1.set_xticklabels([f'#{p}' for p in packets], rotation=45)
            ax1.grid(True, alpha=0.3)
    
    # 2. 长度扩张分析 - 加密开销分析
    ax2 = plt.subplot(2, 3, 2)
    if entropy_data:
        expansion_ratios = [d['length_expansion_ratio'] for d in entropy_data if d['length_expansion_ratio'] > 0]
        packet_nums = [d['packet_number'] for d in entropy_data if d['length_expansion_ratio'] > 0]
        
        if expansion_ratios:
            colors = ['red' if r > 1.2 else 'orange' if r > 1.0 else 'green' for r in expansion_ratios]
            bars = ax2.bar(range(len(expansion_ratios)), expansion_ratios, color=colors, alpha=0.7)
            ax2.set_title('密文长度扩张率', fontsize=12, fontweight='bold')
            ax2.set_xlabel('数据包')
            ax2.set_ylabel('扩张率')
            ax2.axhline(y=1.0, color='black', linestyle='--', alpha=0.5, label='基准线')
            ax2.set_xticks(range(len(packet_nums)))
            ax2.set_xticklabels([f'#{p}' for p in packet_nums], rotation=45)
            ax2.legend()
            ax2.grid(True, alpha=0.3)
    
    # 3. 填充类型分析
    ax3 = plt.subplot(2, 3, 3)
    padding_types = Counter()
    
    for packet_data in analysis_data['detailed_analysis']:
        for layer_name, layer_data in packet_data['layers'].items():
            if 'decoded_data' in layer_data and layer_data['decoded_data']:
                padding_info = layer_data['decoded_data'].get('padding_analysis')
                if padding_info:
                    if padding_info.get('padding_detected'):
                        padding_type = padding_info.get('padding_type', 'Unknown')
                        padding_types[padding_type] += 1
                    else:
                        padding_types['No Padding'] += 1
    
    if padding_types:
        labels = list(padding_types.keys())
        sizes = list(padding_types.values())
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
        ax3.pie(sizes, labels=labels, colors=colors[:len(labels)], autopct='%1.1f%%', startangle=90)
        ax3.set_title('填充类型分布', fontsize=12, fontweight='bold')
    
    # 4. 数据分片大小分布
    ax4 = plt.subplot(2, 3, 4)
    fragment_sizes = []
    for frag_pattern in analysis_data['encryption_analysis']['fragmentation_patterns']:
        if frag_pattern.get('fragment_sizes'):
            fragment_sizes.extend(frag_pattern['fragment_sizes'])
    
    if fragment_sizes:
        ax4.hist(fragment_sizes, bins=min(20, len(set(fragment_sizes))), alpha=0.7, color='skyblue', edgecolor='black')
        ax4.set_title('数据分片大小分布', fontsize=12, fontweight='bold')
        ax4.set_xlabel('分片大小 (字节)')
        ax4.set_ylabel('频次')
        ax4.grid(True, alpha=0.3)
    
    # 5. 改进的数据流时间线
    ax5 = plt.subplot(2, 3, 5)
    timestamps = []
    data_sizes = []
    packet_numbers = []
    
    for packet_data in analysis_data['detailed_analysis']:
        try:
            # 使用数据包序号作为时间轴，更稳定
            packet_numbers.append(packet_data['packet_number'])
            
            total_size = 0
            for layer_data in packet_data['layers'].values():
                if 'decoded_data' in layer_data and layer_data['decoded_data']:
                    # 尝试多种大小字段
                    size_fields = ['frame_length', 'length', 'data_length', 'payload_length']
                    for field in size_fields:
                        if field in layer_data['decoded_data']:
                            size_val = layer_data['decoded_data'][field]
                            if isinstance(size_val, (int, float)) and size_val > 0:
                                total_size += size_val
                                break
            
            if total_size > 0:
                data_sizes.append(total_size)
            else:
                data_sizes.append(0)
        except Exception as e:
            packet_numbers.append(packet_data.get('packet_number', len(packet_numbers)))
            data_sizes.append(0)
    
    if packet_numbers and data_sizes and any(s > 0 for s in data_sizes):
        ax5.plot(packet_numbers, data_sizes, marker='o', linewidth=2, markersize=4, color='blue')
        ax5.set_title('数据包大小变化趋势', fontsize=12, fontweight='bold')
        ax5.set_xlabel('数据包序号')
        ax5.set_ylabel('数据大小 (字节)')
        ax5.grid(True, alpha=0.3)
    
    # 6. 压缩/扩张效果分析
    ax6 = plt.subplot(2, 3, 6)
    if entropy_data:
        compression_stats = {'压缩': 0, '扩张': 0, '无变化': 0}
        
        for comp_data in entropy_data:
            ratio = comp_data['length_expansion_ratio']
            if ratio < 0.95:
                compression_stats['压缩'] += 1
            elif ratio > 1.05:
                compression_stats['扩张'] += 1
            else:
                compression_stats['无变化'] += 1
        
        if any(compression_stats.values()):
            labels = list(compression_stats.keys())
            sizes = list(compression_stats.values())
            colors = ['green', 'red', 'gray']
            wedges, texts, autotexts = ax6.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax6.set_title('数据压缩/扩张分布', fontsize=12, fontweight='bold')
            
            # 美化饼图文字
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
    
    plt.tight_layout(pad=3.0)
    chart_file = os.path.join(output_dir, f'{name}_深度分析图表.png')
    plt.savefig(chart_file, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    return chart_file

def generate_deep_analysis_report(name, analysis_data, output_dir):
    """生成深度分析报告"""
    report = []
    
    # 报告标题
    report.append("="*80)
    report.append("网络数据包深度分析报告")
    report.append("密文与明文特征对比分析")
    report.append("="*80)
    report.append(f"分析时间: {analysis_data['timestamp']}")
    report.append(f"总数据包数: {analysis_data['total_packets']}")
    report.append("")
    
    # 初始化变量
    avg_expansion = 0
    avg_entropy_diff = 0
    compression_count = 0
    
    # 加密分析概览
    entropy_data = analysis_data['encryption_analysis']['entropy_comparison']
    report.append("🔐 加密特征分析概览")
    report.append("-"*50)
    
    if entropy_data:
        avg_expansion = np.mean([d['length_expansion_ratio'] for d in entropy_data if d['length_expansion_ratio'] > 0])
        avg_entropy_diff = np.mean([d['entropy_difference'] for d in entropy_data])
        compression_count = sum(1 for d in entropy_data if d['compression_detected'])
        
        report.append(f"平均长度扩张率: {avg_expansion:.3f}")
        report.append(f"平均熵值增加: {avg_entropy_diff:.3f}")
        report.append(f"检测到压缩的数据包: {compression_count}/{len(entropy_data)}")
        report.append("")
    
    # 详细分析表格
    report.append("📊 密文明文对比详细分析")
    report.append("-"*50)
    report.append(f"{'包号':<8} {'明文长度':<10} {'密文长度':<10} {'扩张率':<8} {'熵值差':<8} {'压缩':<6}")
    report.append("-"*60)
    
    for data in entropy_data:
        compression_mark = "是" if data['compression_detected'] else "否"
        report.append(f"{data['packet_number']:<8} {data['plaintext_length']:<10} {data['ciphertext_length']:<10} "
                     f"{data['length_expansion_ratio']:<8.3f} {data['entropy_difference']:<8.3f} {compression_mark:<6}")
    
    # 填充分析
    report.append("\n🔧 数据填充分析")
    report.append("-"*50)
    
    padding_stats = {'PKCS#7': 0, 'Zero Padding': 0, 'No Padding': 0}
    total_padding_bytes = 0
    
    for packet_data in analysis_data['detailed_analysis']:
        for layer_data in packet_data['layers'].values():
            if 'decoded_data' in layer_data and layer_data['decoded_data']:
                padding_info = layer_data['decoded_data'].get('padding_analysis')
                if padding_info:
                    if padding_info.get('padding_detected'):
                        padding_type = padding_info.get('padding_type', 'Unknown')
                        padding_stats[padding_type] = padding_stats.get(padding_type, 0) + 1
                        total_padding_bytes += padding_info.get('padding_bytes', 0)
                    else:
                        padding_stats['No Padding'] += 1
    
    for padding_type, count in padding_stats.items():
        report.append(f"{padding_type}: {count} 次")
    report.append(f"总填充字节数: {total_padding_bytes}")
    
    # 内容类型分析
    report.append("\n📄 数据内容分析")
    report.append("-"*50)
    
    content_analysis = []
    for packet_data in analysis_data['detailed_analysis']:
        if 'http2' in packet_data['layers']:
            text_content = packet_data['layers']['http2']['decoded_data'].get('text_content', {})
            if text_content.get('readable_text'):
                content_analysis.append({
                    'packet': packet_data['packet_number'],
                    'text_ratio': text_content.get('text_ratio', 0),
                    'content_type': 'HTML' if text_content.get('contains_html') else 
                                   'JSON' if text_content.get('contains_json') else
                                   'Image' if text_content.get('contains_image_data') else 'Text',
                    'sample_text': text_content.get('readable_text', '')[:100]
                })
    
    report.append(f"{'包号':<8} {'可读率':<8} {'类型':<8} {'内容样本':<50}")
    report.append("-"*80)
    for content in content_analysis[:10]:  # 限制显示数量
        report.append(f"{content['packet']:<8} {content['text_ratio']:<8.2f} {content['content_type']:<8} "
                     f"{content['sample_text']:<50}")
    
    # 分片分析
    report.append("\n🧩 数据分片与重组分析")
    report.append("-"*50)
    
    for frag_pattern in analysis_data['encryption_analysis']['fragmentation_patterns']:
        report.append(f"流 ID {frag_pattern['stream_id']}:")
        report.append(f"  分片数量: {frag_pattern['total_fragments']}")
        report.append(f"  大小方差: {frag_pattern['size_variance']:.2f}")
        report.append(f"  检测到间隙: {'是' if frag_pattern['gaps_detected'] else '否'}")
        if frag_pattern['fragment_sizes']:
            avg_size = np.mean(frag_pattern['fragment_sizes'])
            report.append(f"  平均分片大小: {avg_size:.2f} 字节")
        report.append("")
    
    # 安全性评估
    report.append("🛡️ 安全性评估")
    report.append("-"*50)
    
    # 熵值评估
    high_entropy_count = 0
    low_entropy_count = 0
    
    for packet_data in analysis_data['detailed_analysis']:
        if 'tls' in packet_data['layers']:
            entropy = packet_data['layers']['tls']['decoded_data'].get('encrypted_entropy', 0)
            if entropy > 7.5:  # 高熵值阈值
                high_entropy_count += 1
            elif entropy < 6.0:  # 低熵值阈值
                low_entropy_count += 1
    
    report.append(f"高熵值密文包 (>7.5): {high_entropy_count}")
    report.append(f"低熵值密文包 (<6.0): {low_entropy_count}")
    
    if high_entropy_count > low_entropy_count:
        report.append("✅ 加密质量良好，熵值分布正常")
    else:
        report.append("⚠️  部分密文熵值偏低，可能存在模式")
    
    # 建议
    report.append("\n💡 优化建议")
    report.append("-"*50)
    
    if avg_expansion > 1.2:
        report.append("• 考虑优化加密算法或减少填充开销")
    if compression_count > 0:
        report.append("• 检测到数据压缩，建议分析压缩算法效果")
    if total_padding_bytes > 100:
        report.append("• 填充字节较多，可考虑优化填充策略")
    
    report.append("\n" + "="*80)
    report.append("深度分析报告完成")
    report.append("="*80)
    
    # 保存报告
    report_file = os.path.join(output_dir, f'{name}_深度分析报告.txt')
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
    
    # 保存JSON数据
    json_file = os.path.join(output_dir, f'{name}_深度分析数据.json')
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(analysis_data, f, ensure_ascii=False, indent=2, default=str)
    
    return report_file, json_file

def main(target_name):
    """主函数"""
    # 可选择的分析目标
    available_targets = list(name_package_dict.keys())
    print("可用的深度分析目标:")
    for i, target in enumerate(available_targets, 1):
        print(f"{i}. {target}")
        
    print(f"\n当前深度分析目标: {target_name}")
    print(f"对应的过滤器: {name_package_dict[target_name]}")
    
    # 构建pcap文件路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_file = os.path.join(current_dir, f'{target_name}.pcapng')
    
    if not os.path.exists(pcap_file):
        print(f"文件不存在: {pcap_file}")
        return
    
    print("开始深度分析...")
    
    try:
        # 执行深度分析，传入target_name参数以使用对应的过滤器
        analysis_data = deep_packet_analysis(pcap_file, target_name)
        
        # 生成图表
        print("生成分析图表...")
        chart_file = create_deep_analysis_charts(target_name, analysis_data, current_dir)
        print(f"图表已保存: {os.path.basename(chart_file)}")
        
        # 生成报告
        print("生成分析报告...")
        report_file, json_file = generate_deep_analysis_report(target_name, analysis_data, current_dir)
        print(f"报告已保存: {os.path.basename(report_file)}")
        print(f"数据已保存: {os.path.basename(json_file)}")
        
        print("\n深度分析完成！")
        
    except Exception as e:
        print(f"分析过程中出现错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main('五大湖')
    main('奥特曼')
    main('假面骑士')
    main('尼亚加拉瀑布')
    main('孙策')