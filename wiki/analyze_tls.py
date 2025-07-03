#!/usr/bin/env python3
# analyze_tls_pyshark.py
"""
直接在 Python 里用 PyShark 解析 pcapng，针对 tcp.stream==8
提取 TLS Application Data 记录长度 和 HTTP/2 明文字段长度，
深入分析明文切割、填充、加密、组装过程及密文对明文的长度扩张情况。
改进版本：处理TCP分片、优化长度计算、添加数据验证。
"""

import argparse
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

def analyze_tls_structure(pkt, i):
    """分析TLS记录结构"""
    tls_info = {}
    try:
        # TLS记录基本信息
        tls_info['record_length'] = int(pkt.tls.record_length)
        tls_info['content_type'] = int(pkt.tls.record_content_type) if hasattr(pkt.tls, 'record_content_type') else 23
        tls_info['version'] = getattr(pkt.tls, 'record_version', 'Unknown')
        
        # 检查是否为分片数据包
        tls_info['is_fragmented'] = False
        if hasattr(pkt, 'tcp'):
            # 检查TCP分片信息
            if hasattr(pkt.tcp, 'pdu_size'):
                pdu_size = int(pkt.tcp.pdu_size)
                tcp_payload = int(pkt.tcp.len)
                if pdu_size > tcp_payload:
                    tls_info['is_fragmented'] = True
                    tls_info['pdu_size'] = pdu_size
                    tls_info['tcp_payload'] = tcp_payload
        
        # TLS 1.3 AEAD结构分析
        # TLS记录 = 5字节头部 + 加密载荷 + 16字节认证标签
        header_len = 5
        auth_tag_len = 16
        encrypted_payload_len = tls_info['record_length'] - header_len - auth_tag_len
        
        tls_info['header_len'] = header_len
        tls_info['auth_tag_len'] = auth_tag_len
        tls_info['encrypted_payload_len'] = encrypted_payload_len
        
        if i < 3:
            print(f"\n=== TLS记录结构分析 (包 {i}) ===")
            print(f"TLS记录总长度: {tls_info['record_length']} bytes")
            print(f"  - 头部长度: {header_len} bytes")
            print(f"  - 加密载荷: {encrypted_payload_len} bytes")
            print(f"  - 认证标签: {auth_tag_len} bytes")
            print(f"内容类型: {tls_info['content_type']} (23=Application Data)")
            if tls_info['is_fragmented']:
                print(f"分片信息: PDU大小={tls_info.get('pdu_size', 'N/A')}, TCP载荷={tls_info.get('tcp_payload', 'N/A')}")
            
    except Exception as e:
        print(f"TLS结构分析错误 (包 {i}): {e}")
        
    return tls_info

def analyze_http2_structure(pkt, i):
    """分析HTTP/2帧结构和内容 - 修复版本"""
    h2_info = {}
    frame_details = []
    
    try:
        if hasattr(pkt, 'http2'):
            http2_layers = [layer for layer in pkt.layers if layer.layer_name == 'http2']
            h2_info['layer_count'] = len(http2_layers)
            
            total_h2_len = 0
            valid_frames = 0
            
            for layer_idx, layer in enumerate(http2_layers):
                frame_info = {}
                
                # 获取帧载荷长度（不包含9字节帧头部）
                frame_payload_len = 0
                for field in ['length', 'frame_length', 'data_length']:
                    try:
                        if hasattr(layer, field):
                            value = getattr(layer, field)
                            if value and str(value).isdigit():
                                frame_payload_len = int(value)
                                break
                    except:
                        continue
                
                if frame_payload_len > 0:
                    # 完整帧长度 = 9字节头部 + 载荷长度
                    complete_frame_len = 9 + frame_payload_len
                    total_h2_len += complete_frame_len
                    valid_frames += 1
                    
                    frame_info['payload_length'] = frame_payload_len
                    frame_info['complete_length'] = complete_frame_len
                
                # 获取帧长度（不重复添加头部）
                frame_len = 0
                for field in ['length', 'frame_length', 'data_length']:
                    try:
                        if hasattr(layer, field):
                            value = getattr(layer, field)
                            if value and str(value).isdigit():
                                frame_len = int(value)
                                break
                    except:
                        continue
                
                # 只计算载荷长度，帧头部由TLS层统一处理
                if frame_len > 0:
                    total_h2_len += frame_len + 9  # 载荷 + 9字节帧头部
                    valid_frames += 1
                    # 移除重复的帧头部添加
                    if frame_info.get('type_name') != 'Unknown':
                        total_h2_len += 9  # HTTP/2帧头部
                
                frame_details.append(frame_info)
            
            h2_info['total_length'] = total_h2_len
            h2_info['valid_frames'] = valid_frames
            h2_info['frames'] = frame_details
            
            if i < 3:
                print(f"\n=== HTTP/2帧结构分析 (包 {i}) ===")
                print(f"HTTP/2层数量: {h2_info['layer_count']}")
                print(f"有效帧数量: {valid_frames}")
                print(f"总HTTP/2长度: {total_h2_len} bytes (含帧头部)")
                
                for idx, frame in enumerate(frame_details):
                    if frame.get('length', 0) > 0 or frame.get('calculated_length', 0) > 0:
                        print(f"  帧 {idx}: {frame.get('type_name', 'Unknown')}")
                        print(f"    长度: {frame.get('length', frame.get('calculated_length', 'N/A'))} bytes")
                        print(f"    流ID: {frame.get('stream_id', 'N/A')}")
                        
    except Exception as e:
        print(f"HTTP/2结构分析错误 (包 {i}): {e}")
        
    return h2_info

def get_http2_frame_type_name(frame_type):
    """获取HTTP/2帧类型名称"""
    types = {
        0: 'DATA',
        1: 'HEADERS', 
        2: 'PRIORITY',
        3: 'RST_STREAM',
        4: 'SETTINGS',
        5: 'PUSH_PROMISE',
        6: 'PING',
        7: 'GOAWAY',
        8: 'WINDOW_UPDATE',
        9: 'CONTINUATION'
    }
    return types.get(frame_type, f'UNKNOWN({frame_type})')

def calculate_expansion_metrics(tls_info, h2_info, i):
    """计算详细的长度扩张指标 - 修复版本"""
    metrics = {}
    
    try:
        # 基础长度
        tls_total = tls_info['record_length']
        tls_encrypted = tls_info['encrypted_payload_len']
        h2_total = h2_info['total_length']
        
        if h2_total <= 0:
            return None
            
        # 数据合理性检查
        if tls_encrypted < h2_total:
            if i < 5:
                print(f"数据验证失败 (包 {i}): 加密长度({tls_encrypted}) < HTTP/2长度({h2_total})")
                print(f"这表明HTTP/2长度计算可能有误")
            # 不要直接返回None，而是尝试修正
            
        # 各种扩张率计算
        metrics['tls_total_len'] = tls_total
        metrics['tls_encrypted_len'] = tls_encrypted
        metrics['h2_plaintext_len'] = h2_total
        metrics['is_fragmented'] = tls_info.get('is_fragmented', False)
        
        # TLS开销（固定21字节：5字节头部 + 16字节AEAD标签）
        metrics['tls_overhead'] = 21
        metrics['tls_overhead_ratio'] = 21 / h2_total
        
        # 正确的加密扩张计算
        # TLS 1.3: 加密数据 = HTTP/2明文 + 1字节内容类型 + 填充
        expected_encrypted_min = h2_total + 1  # 最少1字节内容类型
        metrics['encryption_expansion'] = max(0, tls_encrypted - expected_encrypted_min)
        metrics['encryption_expansion_ratio'] = metrics['encryption_expansion'] / h2_total if h2_total > 0 else 0
        
        # 总体扩张
        metrics['total_expansion'] = tls_total - h2_total
        metrics['total_expansion_ratio'] = metrics['total_expansion'] / h2_total
        
        # 填充分析
        if metrics['encryption_expansion'] > 0:
            metrics['potential_padding'] = metrics['encryption_expansion']
            metrics['has_padding'] = True
            if metrics['encryption_expansion'] <= 15:
                metrics['padding_type'] = 'alignment'
            else:
                metrics['padding_type'] = 'traffic_analysis_protection'
        else:
            metrics['potential_padding'] = 0
            metrics['has_padding'] = False
            metrics['padding_type'] = 'none'
            
        if i < 3:
            print(f"\n=== 长度扩张分析 (包 {i}) ===")
            print(f"明文长度 (HTTP/2): {h2_total} bytes")
            print(f"加密载荷长度: {tls_encrypted} bytes")
            print(f"TLS记录总长度: {tls_total} bytes")
            print(f"TLS协议开销: {metrics['tls_overhead']} bytes ({100*metrics['tls_overhead_ratio']:.1f}%)")
            print(f"加密扩张: {metrics['encryption_expansion']} bytes ({100*metrics['encryption_expansion_ratio']:.1f}%)")
            print(f"总体扩张: {metrics['total_expansion']} bytes ({100*metrics['total_expansion_ratio']:.1f}%)")
            
            # 数据合理性提示
            if metrics['total_expansion_ratio'] < 0:
                print(f"⚠️  警告：总体扩张为负，数据可能有误")
            if metrics['encryption_expansion_ratio'] < 0:
                print(f"⚠️  警告：加密扩张为负，不符合密码学原理")
                
    except Exception as e:
        print(f"扩张计算错误 (包 {i}): {e}")
        return None
        
    return metrics

def filter_valid_data(df):
    """过滤有效数据，移除明显异常的记录"""
    original_count = len(df)
    
    # 过滤条件
    valid_df = df[
        (df['encryption_expansion'] >= -100) &  # 允许少量负扩张
        (df['encryption_expansion'] <= 1000) &  # 过滤过大的扩张
        (df['h2_plaintext_len'] > 0) &          # HTTP/2长度必须大于0
        (df['tls_total_len'] > 21)              # TLS记录至少包含头部和标签
    ]
    
    filtered_count = len(valid_df)
    print(f"\n=== 数据过滤结果 ===")
    print(f"原始数据包: {original_count}")
    print(f"有效数据包: {filtered_count}")
    print(f"过滤掉: {original_count - filtered_count} ({100*(original_count-filtered_count)/original_count:.1f}%)")
    
    return valid_df

def analyze_stream(pcap_file: str, stream_id: int):
    # display_filter 同时筛选 stream、TLS AppData 和 HTTP/2
    disp_filter = (
        f"tcp.stream eq {stream_id} && "
        f"tls.record.content_type == 23 && http2"
    )
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=disp_filter,
        tshark_path =  'D:\\else\\wireshark\\tshark.exe' 
    )

    rows = []
    frame_type_stats = defaultdict(int)
    fragmented_count = 0
    
    for i, pkt in enumerate(cap):
        try:
            # 时间戳（相对）
            t = float(pkt.frame_info.time_relative)
            
            # 分析TLS结构
            tls_info = analyze_tls_structure(pkt, i)
            if not tls_info:
                continue
                
            # 分析HTTP/2结构
            h2_info = analyze_http2_structure(pkt, i)
            if not h2_info or h2_info['total_length'] <= 0:
                if i < 5:
                    print(f"跳过数据包 {i}: 无有效 HTTP/2 数据")
                continue
            
            # 计算扩张指标
            metrics = calculate_expansion_metrics(tls_info, h2_info, i)
            if not metrics:
                continue
            
            # 统计帧类型
            for frame in h2_info['frames']:
                frame_type = frame.get('type_name', 'Unknown')
                frame_type_stats[frame_type] += 1
            
            # 统计分片数据包
            if metrics['is_fragmented']:
                fragmented_count += 1
            
            # 构建数据行
            row = {
                "time": t,
                "packet_num": i,
                # TLS相关
                "tls_total_len": metrics['tls_total_len'],
                "tls_encrypted_len": metrics['tls_encrypted_len'],
                "tls_overhead": metrics['tls_overhead'],
                # HTTP/2相关
                "h2_plaintext_len": metrics['h2_plaintext_len'],
                "h2_frame_count": h2_info['layer_count'],
                "h2_valid_frames": h2_info['valid_frames'],
                # 扩张指标
                "encryption_expansion": metrics['encryption_expansion'],
                "total_expansion": metrics['total_expansion'],
                "tls_overhead_ratio": metrics['tls_overhead_ratio'],
                "encryption_expansion_ratio": metrics['encryption_expansion_ratio'],
                "total_expansion_ratio": metrics['total_expansion_ratio'],
                # 填充相关
                "potential_padding": metrics['potential_padding'],
                "has_padding": metrics['has_padding'],
                "padding_type": metrics['padding_type'],
                # 分片信息
                "is_fragmented": metrics['is_fragmented'],
            }
            
            rows.append(row)
            
        except Exception as e:
            if i < 5:
                print(f"处理数据包 {i} 时出错: {e}")
            continue
    
    cap.close()
    
    df = pd.DataFrame(rows)
    if df.empty:
        print(f"[!] 在 tcp.stream=={stream_id} 中没有找到 Application Data 记录。")
        return df

    # 过滤有效数据
    df = filter_valid_data(df)
    if df.empty:
        print("[!] 过滤后没有有效数据。")
        return df

    # 打印详细统计信息
    print(f"\n=== 数据包处理统计 ===")
    print(f"总处理数据包: {len(df)}")
    print(f"分片数据包: {fragmented_count} ({100*fragmented_count/len(df):.1f}%)")
    print(f"HTTP/2帧类型分布:")
    for frame_type, count in frame_type_stats.items():
        print(f"  {frame_type}: {count}")
    
    # 分类统计：大包 vs 小包
    large_packets = df[df['h2_plaintext_len'] >= 1000]
    small_packets = df[df['h2_plaintext_len'] < 1000]
    
    print(f"\n=== 按数据包大小分类统计 ===")
    print(f"大数据包 (>=1KB): {len(large_packets)} 个")
    if len(large_packets) > 0:
        print(f"  平均扩张率: {100*large_packets['total_expansion_ratio'].mean():.2f}%")
    print(f"小数据包 (<1KB): {len(small_packets)} 个")
    if len(small_packets) > 0:
        print(f"  平均扩张率: {100*small_packets['total_expansion_ratio'].mean():.2f}%")
    
    # 长度统计
    length_cols = ["tls_total_len", "tls_encrypted_len", "h2_plaintext_len", 
                   "tls_overhead", "encryption_expansion", "total_expansion", "potential_padding"]
    stats = df[length_cols].describe(percentiles=[.25, .5, .75, .9, .95])
    print("\n=== 长度统计 (Bytes) ===")
    print(stats.to_string())
    
    # 扩张率统计
    expansion_cols = ["tls_overhead_ratio", "encryption_expansion_ratio", "total_expansion_ratio"]
    print("\n=== 扩张率统计 ===")
    for col in expansion_cols:
        mean_val = df[col].mean()
        median_val = df[col].median()
        print(f"{col}: 平均 {100*mean_val:.2f}%, 中位数 {100*median_val:.2f}%")
    
    # 填充分析
    padding_packets = df[df['has_padding'] == True]
    if len(padding_packets) > 0:
        print(f"\n=== 填充分析 ===")
        print(f"包含填充的数据包: {len(padding_packets)}/{len(df)} ({100*len(padding_packets)/len(df):.1f}%)")
        print(f"平均填充长度: {padding_packets['potential_padding'].mean():.1f} bytes")
        print(f"最大填充长度: {padding_packets['potential_padding'].max()} bytes")
        
        # 按填充类型统计
        padding_types = padding_packets['padding_type'].value_counts()
        print("填充类型分布:")
        for ptype, count in padding_types.items():
            print(f"  {ptype}: {count}")
    
    # 绘制多维度对比图
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # 长度对比
    df.set_index("time")[["tls_total_len", "tls_encrypted_len", "h2_plaintext_len"]].plot(
        ax=axes[0,0], title="Length Comparison: TLS vs HTTP/2", ylabel="Bytes")
    
    # 扩张分解
    df.set_index("time")[["tls_overhead", "encryption_expansion"]].plot(
        ax=axes[0,1], title="Expansion Breakdown: Protocol vs Encryption", ylabel="Bytes")
    
    # 扩张率趋势
    df.set_index("time")[["tls_overhead_ratio", "encryption_expansion_ratio", "total_expansion_ratio"]].plot(
        ax=axes[1,0], title="Expansion Ratio Trends", ylabel="Ratio")
    
    # 数据包大小分布
    df['h2_plaintext_len'].hist(bins=50, ax=axes[1,1], alpha=0.7)
    axes[1,1].set_title("HTTP/2 Plaintext Size Distribution")
    axes[1,1].set_xlabel("Bytes")
    axes[1,1].set_ylabel("Count")
    axes[1,1].set_yscale('log')
    
    plt.tight_layout()
    plt.show()

    return df

def main():
    parser = argparse.ArgumentParser(
        description="深度分析 TLS 1.3 & HTTP/2 明文切割、填充、加密、组装过程及长度扩张 (改进版)"
    )
    parser.add_argument("--pcap", help="输入 pcapng 文件（已解密）")
    parser.add_argument("--stream", type=int, default=8,
                        help="tcp.stream 编号（默认 8）")
    parser.add_argument("--no-plot", action="store_true",
                        help="不显示绘图，只输出统计")
    args = parser.parse_args()

    df = analyze_stream(args.pcap, args.stream)
    if args.no_plot:
        plt.close("all")

if __name__ == "__main__":
    main()
