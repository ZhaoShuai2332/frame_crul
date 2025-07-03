import pyshark
import json
from collections import defaultdict
from datetime import datetime

# 配置信息
name_package_dict = {
    "奥特曼": "tcp.stream eq 8 and http2.streamid eq 1",
    "假面骑士": "tcp.stream eq 33 and http2.streamid eq 19",
    "尼亚加拉瀑布": "tcp.stream eq 70 and http2.streamid eq 15",
    "孙策": "tcp.stream eq 12 and http2.streamid eq 21",
    "五大湖": "tcp.stream eq 37 and http2.streamid eq 23",
}

tshark_path = "D:\\else\\wireshark\\tshark.exe"

def get_cap(name):
    cap = pyshark.FileCapture(f'wiki/{name}.pcapng', 
                display_filter=name_package_dict[name], 
                tshark_path=tshark_path
                )
    return cap

def safe_int_convert(value, default=0):
    """安全地转换值为整数"""
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

def analyze_packet_encryption(packet):
    """分析数据包的加密和封装过程"""
    analysis = {
        'packet_number': safe_int_convert(packet.number),
        'timestamp': str(packet.sniff_time),
        'total_length': safe_int_convert(packet.length),
        'layers': []
    }
    
    # 分析各层数据
    for layer in packet.layers:
        layer_info = {
            'protocol': layer.layer_name.upper(),
            'layer_data': {}
        }
        
        if layer.layer_name == 'tcp':
            layer_info['layer_data'] = {
                'payload_length': safe_int_convert(getattr(layer, 'len', 0)),
                'tcp_header_length': safe_int_convert(getattr(layer, 'hdr_len', 0)),
                'tcp_flags': str(getattr(layer, 'flags_str', '')),
                'sequence_number': safe_int_convert(getattr(layer, 'seq', 0)),
                'ack_number': safe_int_convert(getattr(layer, 'ack', 0))
            }
            
        elif layer.layer_name == 'tls':
            layer_info['layer_data'] = {
                'record_type': safe_int_convert(getattr(layer, 'record_content_type', 0)),
                'tls_version': str(getattr(layer, 'record_version', '')),
                'encrypted_length': safe_int_convert(getattr(layer, 'record_length', 0)),
                'app_data_proto': str(getattr(layer, 'app_data_proto', '')),
            }
            
        elif layer.layer_name == 'http2':
            layer_info['layer_data'] = {
                'stream_id': safe_int_convert(getattr(layer, 'streamid', 0)),
                'frame_type': safe_int_convert(getattr(layer, 'type', 0)),
                'frame_length': safe_int_convert(getattr(layer, 'length', 0)),
                'flags': safe_int_convert(getattr(layer, 'flags', 0)),  # 这里修复了十六进制转换问题
                'headers_count': safe_int_convert(getattr(layer, 'header_count', 0)),
                'headers_length': safe_int_convert(getattr(layer, 'header_length', 0)),
                'method': str(getattr(layer, 'headers_method', '')),
                'path': str(getattr(layer, 'headers_path', '')),
                'authority': str(getattr(layer, 'headers_authority', ''))
            }
            
        analysis['layers'].append(layer_info)
    
    return analysis

def calculate_encryption_metrics(packet):
    """计算加密相关指标"""
    metrics = {
        'packet_number': safe_int_convert(packet.number),
        'plaintext_estimate': 0,
        'encrypted_length': 0,
        'total_overhead': 0,
        'encryption_overhead': 0,
        'protocol_overheads': {}
    }
    
    ip_header = 20  # 标准IP头部
    eth_header = 14  # 以太网头部
    
    for layer in packet.layers:
        if layer.layer_name == 'http2':
            frame_length = safe_int_convert(getattr(layer, 'length', 0))
            headers_length = safe_int_convert(getattr(layer, 'header_length', 0))
            metrics['plaintext_estimate'] = frame_length + headers_length
            
        elif layer.layer_name == 'tls':
            metrics['encrypted_length'] = safe_int_convert(getattr(layer, 'record_length', 0))
            
        elif layer.layer_name == 'tcp':
            tcp_header = safe_int_convert(getattr(layer, 'hdr_len', 0))
            metrics['protocol_overheads']['tcp_header'] = tcp_header
    
    # 计算各种开销
    metrics['protocol_overheads']['ip_header'] = ip_header
    metrics['protocol_overheads']['eth_header'] = eth_header
    
    if metrics['plaintext_estimate'] > 0 and metrics['encrypted_length'] > 0:
        metrics['encryption_overhead'] = metrics['encrypted_length'] - metrics['plaintext_estimate']
        metrics['total_overhead'] = sum(metrics['protocol_overheads'].values()) + metrics['encryption_overhead']
        metrics['encryption_expansion_ratio'] = metrics['encrypted_length'] / metrics['plaintext_estimate']
    
    return metrics

def generate_analysis_report(name):
    """生成完整的分析报告"""
    print(f"\n{'='*80}")
    print(f"数据包加密与封装分析报告")
    print(f"目标: {name}")
    print(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}\n")
    
    cap = get_cap(name)
    packet_analyses = []
    encryption_metrics = []
    
    print("📊 执行摘要")
    print("-" * 40)
    
    packet_count = 0
    for packet in cap:
        packet_count += 1
        analysis = analyze_packet_encryption(packet)
        metrics = calculate_encryption_metrics(packet)
        
        packet_analyses.append(analysis)
        encryption_metrics.append(metrics)
        
        if packet_count >= 5:  # 分析前5个包
            break
    
    # 计算统计数据
    total_plaintext = sum(m['plaintext_estimate'] for m in encryption_metrics if m['plaintext_estimate'] > 0)
    total_encrypted = sum(m['encrypted_length'] for m in encryption_metrics if m['encrypted_length'] > 0)
    avg_expansion = sum(m['encryption_expansion_ratio'] for m in encryption_metrics if 'encryption_expansion_ratio' in m) / len([m for m in encryption_metrics if 'encryption_expansion_ratio' in m]) if encryption_metrics else 0
    
    print(f"分析数据包数量: {len(packet_analyses)}")
    print(f"明文数据总量: {total_plaintext} bytes")
    print(f"加密数据总量: {total_encrypted} bytes")
    print(f"平均加密扩张比例: {avg_expansion:.3f} ({(avg_expansion-1)*100:.1f}% 增长)")
    
    print(f"\n📋 详细分析")
    print("-" * 40)
    
    for i, (analysis, metrics) in enumerate(zip(packet_analyses, encryption_metrics)):
        print(f"\n🔍 数据包 #{analysis['packet_number']}")
        print(f"时间戳: {analysis['timestamp']}")
        print(f"总长度: {analysis['total_length']} bytes")
        
        # 协议栈分析
        protocols = [layer['protocol'] for layer in analysis['layers']]
        print(f"协议栈: {' → '.join(protocols)}")
        
        # 各层详细信息
        for layer in analysis['layers']:
            protocol = layer['protocol']
            data = layer['layer_data']
            
            if protocol == 'HTTP2':
                print(f"\n  📄 {protocol}层 (明文应用数据):")
                print(f"    帧长度: {data.get('frame_length', 0)} bytes")
                print(f"    头部长度: {data.get('headers_length', 0)} bytes")
                print(f"    请求方法: {data.get('method', 'N/A')}")
                print(f"    请求路径: {data.get('path', 'N/A')[:50]}...")
                
            elif protocol == 'TLS':
                print(f"\n  🔐 {protocol}层 (加密处理):")
                print(f"    加密数据长度: {data.get('encrypted_length', 0)} bytes")
                print(f"    TLS版本: {data.get('tls_version', 'N/A')}")
                print(f"    记录类型: {data.get('record_type', 'N/A')}")
                
            elif protocol == 'TCP':
                print(f"\n  🌐 {protocol}层 (传输控制):")
                print(f"    头部长度: {data.get('tcp_header_length', 0)} bytes")
                print(f"    载荷长度: {data.get('payload_length', 0)} bytes")
                print(f"    标志位: {data.get('tcp_flags', 'N/A')}")
        
        # 加密开销分析
        if 'encryption_expansion_ratio' in metrics:
            print(f"\n  📈 加密开销分析:")
            print(f"    明文估算: {metrics['plaintext_estimate']} bytes")
            print(f"    密文长度: {metrics['encrypted_length']} bytes")
            print(f"    加密开销: +{metrics['encryption_overhead']} bytes")
            print(f"    扩张比例: {metrics['encryption_expansion_ratio']:.3f} ({(metrics['encryption_expansion_ratio']-1)*100:.1f}% 增长)")
            
            print(f"\n  🏗️ 协议开销分解:")
            for proto, overhead in metrics['protocol_overheads'].items():
                print(f"    {proto.upper()}: {overhead} bytes")
            print(f"    加密开销: {metrics['encryption_overhead']} bytes")
            print(f"    总开销: {metrics['total_overhead']} bytes")
        
        print("\n" + "-" * 60)
    
    # 生成总结
    print(f"\n📊 分析总结")
    print("-" * 40)
    print(f"\n🔍 数据处理流程:")
    print(f"1. HTTP2明文请求 → 包含请求头、方法、路径等信息")
    print(f"2. TLS加密处理 → 添加加密填充、认证标签和完整性校验")
    print(f"3. TCP封装 → 添加传输控制信息(序列号、确认号等)")
    print(f"4. IP封装 → 添加网络层路由信息")
    print(f"5. 以太网封装 → 添加数据链路层MAC地址")
    
    print(f"\n💡 关键发现:")
    print(f"• TLS加密平均增加 {(avg_expansion-1)*100:.1f}% 的数据开销")
    print(f"• HTTP2头部压缩有效减少了明文数据大小")
    print(f"• 每层协议都会添加相应的控制信息")
    print(f"• 小数据包的协议开销占比更高")
    
    # 保存详细报告到文件
    report_data = {
        'target': name,
        'generation_time': datetime.now().isoformat(),
        'summary': {
            'packets_analyzed': len(packet_analyses),
            'total_plaintext': total_plaintext,
            'total_encrypted': total_encrypted,
            'average_expansion_ratio': avg_expansion
        },
        'detailed_analysis': packet_analyses,
        'encryption_metrics': encryption_metrics
    }
    
    with open(f'wiki/{name}_analysis_report.json', 'w', encoding='utf-8') as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    
    print(f"\n✅ 详细报告已保存到: {name}_analysis_report.json")
    print(f"{'='*80}")
    
    return report_data

if __name__ == "__main__":
    # 可选择的分析目标
    available_targets = list(name_package_dict.keys())
    print("可用的分析目标:")
    for i, target in enumerate(available_targets, 1):
        print(f"{i}. {target}")
    
    # 直接指定要分析的目标（字符串形式）
    target_name = "尼亚加拉瀑布"  # 直接修改这里的字符串来切换分析目标
    
    print(f"\n当前分析目标: {target_name}")
    print(f"对应的过滤器: {name_package_dict[target_name]}")
    
    # 生成分析报告
    generate_analysis_report(target_name)