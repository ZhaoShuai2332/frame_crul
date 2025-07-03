import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

import scapy
import pyshark

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
                tshark_path='D:\\else\\wireshark\\tshark.exe'
                )

    return cap

cap = get_cap("尼亚加拉瀑布")
for i in cap:
    print(f"\n=== 数据包 {i.number} ===")
    print(f"时间戳: {i.sniff_time}")
    print(f"长度: {i.length}")
    
    # 按协议层次展示
    for layer_num, layer in enumerate(i.layers, 1):
        print(f"\n第{layer_num}层 - {layer.layer_name.upper()}协议:")
        print("-" * 40)
        
        # 获取该层的所有字段
        layer_fields = []
        for field_name in dir(layer):
            if not field_name.startswith('_') and not callable(getattr(layer, field_name)):
                try:
                    field_value = getattr(layer, field_name)
                    if field_value is not None:
                        layer_fields.append((field_name, field_value))
                except:
                    continue
        
        # 按字段名排序并显示
        for field_name, field_value in sorted(layer_fields):
            print(f"  {field_name}: {field_value}")
    
    print("\n" + "=" * 60)
    break  # 只显示第一个包作为示例
