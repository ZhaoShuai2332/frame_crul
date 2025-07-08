from collections import Counter
from math import log2

def hex_entropy(hex_str: str) -> float:
    """计算十六进制字符串的香农熵
    
    Args:
        hex_str: 十六进制字符串
        
    Returns:
        float: 熵值 (bit/char)
        
    Raises:
        ValueError: 当输入不包含有效十六进制字符时
    """
    # 清理输入，只保留有效的十六进制字符
    clean = ''.join(c.lower() for c in hex_str if c.lower() in '0123456789abcdef')
    
    # 空字符串的熵定义为0
    if not clean:
        return 0.0
    
    # 计算字符频率
    counts = Counter(clean)
    total = len(clean)
    
    # 计算香农熵
    entropy = -sum((cnt/total) * log2(cnt/total) for cnt in counts.values())
    return entropy

def byte_entropy(data: bytes) -> float:
    """计算字节数据的香农熵
    
    Args:
        data: 字节数据
        
    Returns:
        float: 熵值 (bit/byte)
    """
    if not data:
        return 0.0
        
    counts = Counter(data)
    total = len(data)
    
    entropy = -sum((cnt/total) * log2(cnt/total) for cnt in counts.values())
    return entropy

def analyze_network_data(data_input):
    """分析网络数据的熵值"""
    if isinstance(data_input, str):
        # 十六进制字符串
        if all(c.lower() in '0123456789abcdef' for c in data_input.replace(' ', '').replace(':', '')):
            clean_hex = data_input.replace(' ', '').replace(':', '')
            byte_data = bytes.fromhex(clean_hex)
            return {
                'hex_entropy': hex_entropy(clean_hex),
                'byte_entropy': byte_entropy(byte_data),
                'data_length_chars': len(clean_hex),
                'data_length_bytes': len(byte_data)
            }
    elif isinstance(data_input, bytes):
        # 字节数据
        return {
            'byte_entropy': byte_entropy(data_input),
            'data_length_bytes': len(data_input)
        }
    
    raise ValueError("不支持的数据格式")

# 测试代码
if __name__ == "__main__":
    test_bytes = b""
    print(f"字节数据熵 = {byte_entropy(test_bytes):.4f} bit/byte")