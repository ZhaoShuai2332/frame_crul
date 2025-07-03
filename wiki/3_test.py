import json
from datetime import datetime
import os
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np
from matplotlib.patches import Rectangle
import seaborn as sns

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

def load_json_report(filename):
    """加载JSON报告文件"""
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def format_bytes(bytes_value):
    """格式化字节数为可读格式"""
    if bytes_value < 1024:
        return f"{bytes_value} B"
    elif bytes_value < 1024 * 1024:
        return f"{bytes_value / 1024:.2f} KB"
    else:
        return f"{bytes_value / (1024 * 1024):.2f} MB"

def create_charts(json_data, output_dir):
    """生成各种图表"""
    target = json_data['target']
    
    # 设置图表样式
    plt.style.use('seaborn-v0_8')
    
    # 1. 数据包大小分布图
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle(f'{target} - 网络数据包分析图表', fontsize=16, fontweight='bold')
    
    # 提取数据
    packet_numbers = []
    packet_sizes = []
    plaintext_sizes = []
    encrypted_sizes = []
    expansion_ratios = []
    
    for packet in json_data['detailed_analysis']:
        packet_numbers.append(packet['packet_number'])
        packet_sizes.append(packet['total_length'])
    
    for metric in json_data['encryption_metrics']:
        plaintext_sizes.append(metric['plaintext_estimate'])
        encrypted_sizes.append(metric['encrypted_length'])
        if 'encryption_expansion_ratio' in metric and metric['encryption_expansion_ratio'] > 0:
            expansion_ratios.append(metric['encryption_expansion_ratio'])
        else:
            expansion_ratios.append(0)
    
    # 图表1: 数据包大小分布
    ax1.bar(range(len(packet_numbers)), packet_sizes, color='skyblue', alpha=0.7)
    ax1.set_title('数据包大小分布', fontweight='bold')
    ax1.set_xlabel('数据包序号')
    ax1.set_ylabel('大小 (字节)')
    ax1.set_xticks(range(len(packet_numbers)))
    ax1.set_xticklabels([f'#{num}' for num in packet_numbers], rotation=45)
    
    # 添加数值标签
    for i, v in enumerate(packet_sizes):
        ax1.text(i, v + max(packet_sizes) * 0.01, f'{v}B', ha='center', va='bottom', fontsize=8)
    
    # 图表2: 明文vs加密数据对比
    x = np.arange(len(packet_numbers))
    width = 0.35
    
    bars1 = ax2.bar(x - width/2, plaintext_sizes, width, label='明文估计', color='lightgreen', alpha=0.8)
    bars2 = ax2.bar(x + width/2, encrypted_sizes, width, label='加密长度', color='lightcoral', alpha=0.8)
    
    ax2.set_title('明文 vs 加密数据对比', fontweight='bold')
    ax2.set_xlabel('数据包序号')
    ax2.set_ylabel('大小 (字节)')
    ax2.set_xticks(x)
    ax2.set_xticklabels([f'#{num}' for num in packet_numbers])
    ax2.legend()
    
    # 图表3: 加密膨胀率
    valid_ratios = [r for r in expansion_ratios if r > 0]
    valid_packets = [packet_numbers[i] for i, r in enumerate(expansion_ratios) if r > 0]
    
    if valid_ratios:
        colors = ['red' if r > 1.1 else 'orange' if r > 1.0 else 'green' for r in valid_ratios]
        bars = ax3.bar(range(len(valid_ratios)), valid_ratios, color=colors, alpha=0.7)
        ax3.set_title('加密膨胀率分析', fontweight='bold')
        ax3.set_xlabel('数据包序号')
        ax3.set_ylabel('膨胀率')
        ax3.set_xticks(range(len(valid_ratios)))
        ax3.set_xticklabels([f'#{num}' for num in valid_packets], rotation=45)
        ax3.axhline(y=1.0, color='black', linestyle='--', alpha=0.5, label='基准线(1.0)')
        ax3.legend()
        
        # 添加百分比标签
        for i, v in enumerate(valid_ratios):
            ax3.text(i, v + max(valid_ratios) * 0.01, f'{v:.1%}', ha='center', va='bottom', fontsize=8)
    
    # 图表4: 协议开销饼图
    if json_data['encryption_metrics']:
        overheads = json_data['encryption_metrics'][0]['protocol_overheads']
        labels = ['TCP头部', 'IP头部', '以太网头部']
        sizes = [overheads.get('tcp_header', 0), overheads.get('ip_header', 0), overheads.get('eth_header', 0)]
        colors = ['#ff9999', '#66b3ff', '#99ff99']
        
        wedges, texts, autotexts = ax4.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax4.set_title('协议开销分布', fontweight='bold')
        
        # 美化饼图文字
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
    
    plt.tight_layout()
    chart_file = os.path.join(output_dir, f'{target}_分析图表.png')
    plt.savefig(chart_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. 时间序列分析图
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
    fig.suptitle(f'{target} - 时间序列分析', fontsize=14, fontweight='bold')
    
    # 提取时间戳
    timestamps = []
    for packet in json_data['detailed_analysis']:
        timestamp_str = packet['timestamp']
        # 解析时间戳
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            timestamps.append(timestamp)
        except:
            timestamps.append(datetime.now())
    
    # 时间vs数据包大小
    ax1.plot(timestamps, packet_sizes, marker='o', linewidth=2, markersize=6, color='blue')
    ax1.set_title('数据包大小时间序列', fontweight='bold')
    ax1.set_xlabel('时间')
    ax1.set_ylabel('数据包大小 (字节)')
    ax1.grid(True, alpha=0.3)
    
    # 时间vs加密膨胀率
    if valid_ratios and len(timestamps) >= len(valid_ratios):
        valid_timestamps = timestamps[:len(valid_ratios)]
        ax2.plot(valid_timestamps, valid_ratios, marker='s', linewidth=2, markersize=6, color='red')
        ax2.set_title('加密膨胀率时间序列', fontweight='bold')
        ax2.set_xlabel('时间')
        ax2.set_ylabel('膨胀率')
        ax2.axhline(y=1.0, color='black', linestyle='--', alpha=0.5)
        ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    timeline_file = os.path.join(output_dir, f'{target}_时间序列.png')
    plt.savefig(timeline_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    # 3. 协议层分析热力图
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 统计协议层出现频率
    protocol_stats = {}
    for packet in json_data['detailed_analysis']:
        for layer in packet['layers']:
            protocol = layer['protocol']
            if protocol not in protocol_stats:
                protocol_stats[protocol] = 0
            protocol_stats[protocol] += 1
    
    protocols = list(protocol_stats.keys())
    frequencies = list(protocol_stats.values())
    
    # 创建热力图数据
    heatmap_data = np.array(frequencies).reshape(1, -1)
    
    im = ax.imshow(heatmap_data, cmap='YlOrRd', aspect='auto')
    ax.set_xticks(range(len(protocols)))
    ax.set_xticklabels(protocols, rotation=45)
    ax.set_yticks([0])
    ax.set_yticklabels(['频率'])
    ax.set_title(f'{target} - 协议层使用频率热力图', fontweight='bold')
    
    # 添加数值标签
    for i, freq in enumerate(frequencies):
        ax.text(i, 0, str(freq), ha='center', va='center', fontweight='bold')
    
    plt.colorbar(im, ax=ax, label='使用次数')
    plt.tight_layout()
    heatmap_file = os.path.join(output_dir, f'{target}_协议热力图.png')
    plt.savefig(heatmap_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    return [chart_file, timeline_file, heatmap_file]

def generate_readable_report(json_data, include_charts=True):
    """生成可读的报告"""
    report = []
    
    # 报告标题
    report.append("="*80)
    report.append(f"网络数据包分析报告 - {json_data['target']}")
    report.append("="*80)
    report.append(f"生成时间: {json_data['generation_time']}")
    report.append("")
    
    # 总体概况
    summary = json_data['summary']
    report.append("📊 总体分析概况")
    report.append("-"*40)
    report.append(f"分析数据包数量: {summary['packets_analyzed']} 个")
    report.append(f"明文数据总量: {format_bytes(summary['total_plaintext'])}")
    report.append(f"加密数据总量: {format_bytes(summary['total_encrypted'])}")
    report.append(f"平均加密膨胀率: {summary['average_expansion_ratio']:.2%}")
    report.append("")
    
    # 图表说明
    if include_charts:
        report.append("📈 可视化图表")
        report.append("-"*40)
        report.append("本报告包含以下图表文件:")
        report.append("• 分析图表.png - 包含数据包大小分布、明文vs加密对比、膨胀率分析、协议开销分布")
        report.append("• 时间序列.png - 数据包大小和膨胀率的时间变化趋势")
        report.append("• 协议热力图.png - 各协议层的使用频率分析")
        report.append("")
    
    # 详细数据包分析
    report.append("📦 详细数据包分析")
    report.append("-"*40)
    
    for i, packet in enumerate(json_data['detailed_analysis'], 1):
        report.append(f"\n数据包 #{packet['packet_number']} (第{i}个分析包)")
        report.append(f"  时间戳: {packet['timestamp']}")
        report.append(f"  总长度: {format_bytes(packet['total_length'])}")
        
        # 协议层分析
        report.append("  协议层结构:")
        for layer in packet['layers']:
            protocol = layer['protocol']
            data = layer['layer_data']
            
            if protocol == 'TCP' and data:
                report.append(f"    ├─ {protocol}: 载荷长度={format_bytes(data.get('payload_length', 0))}, 头部长度={data.get('tcp_header_length', 0)}B")
                report.append(f"       序列号={data.get('sequence_number', 0)}, 确认号={data.get('ack_number', 0)}")
                
            elif protocol == 'TLS' and data:
                record_type = data.get('record_type', 0)
                record_type_name = "应用数据" if record_type == 23 else f"类型{record_type}"
                report.append(f"    ├─ {protocol}: {record_type_name}, 版本={data.get('tls_version', 'N/A')}")
                report.append(f"       加密长度={format_bytes(data.get('encrypted_length', 0))}")
                
            elif protocol == 'HTTP2' and data:
                frame_types = {0: "数据帧", 1: "头部帧", 2: "优先级帧", 3: "重置帧", 4: "设置帧"}
                frame_type_name = frame_types.get(data.get('frame_type', 0), f"类型{data.get('frame_type', 0)}")
                report.append(f"    ├─ {protocol}: {frame_type_name}, 流ID={data.get('stream_id', 0)}")
                report.append(f"       帧长度={format_bytes(data.get('frame_length', 0))}, 头部数量={data.get('headers_count', 0)}")
                
                if data.get('method'):
                    report.append(f"       请求: {data.get('method')} {data.get('path', '')}")
                    report.append(f"       主机: {data.get('authority', '')}")
            else:
                report.append(f"    ├─ {protocol}")
    
    # 加密指标分析
    report.append("\n🔐 加密性能指标")
    report.append("-"*40)
    
    # 创建表格
    report.append("\n数据包加密分析表:")
    report.append(f"{'包号':<8} {'明文估计':<12} {'加密长度':<12} {'膨胀率':<10} {'加密开销':<10} {'总开销':<10}")
    report.append("-"*70)
    
    for metric in json_data['encryption_metrics']:
        packet_num = metric['packet_number']
        plaintext = format_bytes(metric['plaintext_estimate'])
        encrypted = format_bytes(metric['encrypted_length'])
        
        if 'encryption_expansion_ratio' in metric:
            ratio = f"{metric['encryption_expansion_ratio']:.2%}"
        else:
            ratio = "N/A"
            
        enc_overhead = metric['encryption_overhead']
        total_overhead = metric['total_overhead']
        
        report.append(f"{packet_num:<8} {plaintext:<12} {encrypted:<12} {ratio:<10} {enc_overhead:<10} {total_overhead:<10}")
    
    # 协议开销分析
    report.append("\n📡 协议开销分析")
    report.append("-"*40)
    if json_data['encryption_metrics']:
        overheads = json_data['encryption_metrics'][0]['protocol_overheads']
        report.append(f"TCP头部开销: {overheads.get('tcp_header', 0)} 字节")
        report.append(f"IP头部开销: {overheads.get('ip_header', 0)} 字节")
        report.append(f"以太网头部开销: {overheads.get('eth_header', 0)} 字节")
        total_protocol_overhead = sum(overheads.values())
        report.append(f"协议总开销: {total_protocol_overhead} 字节")
    
    # 关键发现
    report.append("\n🔍 关键发现")
    report.append("-"*40)
    
    # 分析加密效率
    valid_ratios = [m['encryption_expansion_ratio'] for m in json_data['encryption_metrics'] 
                   if 'encryption_expansion_ratio' in m and m['encryption_expansion_ratio'] > 0]
    
    if valid_ratios:
        avg_ratio = sum(valid_ratios) / len(valid_ratios)
        max_ratio = max(valid_ratios)
        min_ratio = min(valid_ratios)
        
        report.append(f"• 加密膨胀率范围: {min_ratio:.2%} - {max_ratio:.2%}")
        report.append(f"• 平均加密膨胀率: {avg_ratio:.2%}")
        
        if avg_ratio < 1.0:
            report.append("• 数据压缩效果显著，加密后数据量减少")
        elif avg_ratio > 1.1:
            report.append("• 加密开销较高，需要优化")
        else:
            report.append("• 加密开销适中")
    
    # 数据传输模式分析
    frame_types = {}
    for packet in json_data['detailed_analysis']:
        for layer in packet['layers']:
            if layer['protocol'] == 'HTTP2' and layer['layer_data']:
                frame_type = layer['layer_data'].get('frame_type', 0)
                frame_types[frame_type] = frame_types.get(frame_type, 0) + 1
    
    if frame_types:
        report.append(f"• HTTP2帧类型分布:")
        frame_names = {0: "数据帧", 1: "头部帧"}
        for frame_type, count in frame_types.items():
            name = frame_names.get(frame_type, f"类型{frame_type}")
            report.append(f"  - {name}: {count} 个")
    
    report.append("\n" + "="*80)
    report.append("报告生成完成")
    report.append("="*80)
    
    return "\n".join(report)

def main():
    """主函数"""
    # 获取当前脚本所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 查找JSON报告文件
    json_files = [f for f in os.listdir(current_dir) if f.endswith('_analysis_report.json')]
    
    if not json_files:
        print("未找到分析报告文件")
        return
    
    for json_file in json_files:
        print(f"\n处理文件: {json_file}")
        
        # 使用完整路径加载JSON数据
        full_path = os.path.join(current_dir, json_file)
        json_data = load_json_report(full_path)
        
        # 生成图表
        try:
            print("正在生成图表...")
            chart_files = create_charts(json_data, current_dir)
            print(f"图表已生成: {[os.path.basename(f) for f in chart_files]}")
            include_charts = True
        except Exception as e:
            print(f"图表生成失败: {e}")
            print("将生成不包含图表的报告")
            include_charts = False
        
        # 生成可读报告
        readable_report = generate_readable_report(json_data, include_charts)
        
        # 保存为文本文件
        output_file = os.path.join(current_dir, json_file.replace('_analysis_report.json', '_可读报告.txt'))
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(readable_report)
        
        print(f"可读报告已保存为: {os.path.basename(output_file)}")
        
        # 同时在控制台显示
        print("\n" + "="*50)
        print("报告预览:")
        print("="*50)
        print(readable_report[:2000] + "..." if len(readable_report) > 2000 else readable_report)

if __name__ == "__main__":
    main()