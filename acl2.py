from typing import List, Tuple, Union

Range = Tuple[int, int]       # Một khoảng: (start, end)
RangeList = List[Range]       # Một rangelist: nhiều khoảng



# Định nghĩa lớp Rule (một ACL rule)
class Rule:
    def __init__(self, srcIP: RangeList, srcPort: Union[int, str],
                 dstIP: RangeList, dstPort: Union[int, str],
                 protocol: Union[str, None], action: str, name=""):
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.protocol = protocol
        self.action = action
        self.name = name

    def match_range(self, rlist: RangeList, vlist: RangeList) -> bool:
        #Kiểm tra 2 range list có giao nhau không
        for (a1, a2) in rlist:
            for (b1, b2) in vlist:
                if max(a1, b1) <= min(a2, b2):
                    return True
        return False

    def match_value(self, rule_val, pkt_val) -> bool:
        """So khớp một giá trị (có thể là any)"""
        return rule_val == "any" or pkt_val == "any" or rule_val == pkt_val

    def match(self, packet) -> bool:
        """Kiểm tra packet có match rule này không"""
        # Check IPs
        if not self.match_range(self.srcIP, packet.srcIP):
            return False
        if not self.match_range(self.dstIP, packet.dstIP):
            return False
        # Check ports
        if not self.match_value(self.srcPort, packet.srcPort):
            return False
        if not self.match_value(self.dstPort, packet.dstPort):
            return False
        # Check protocol
        if not self.match_value(self.protocol, packet.protocol):
            return False
        return True


# ---------------------------
# Định nghĩa Packet (verification rule kiểm chứng)
# ---------------------------
class Packet:
    def __init__(self, srcIP: RangeList, srcPort, dstIP: RangeList, dstPort, protocol):
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.protocol = protocol


# ---------------------------
# Hàm quyết định action dựa trên ACL
# ---------------------------
def acl_decision(rules: List[Rule], packet: Packet) -> str:
    """Trả về action của packet theo ACL (ưu tiên rule đầu tiên match)"""
    for rule in rules:
        if rule.match(packet):
            return rule.action
    return "deny"   # default deny


# ---------------------------
# Hàm kiểm chứng nhiều verification rule
# ---------------------------
def verify(rules: List[Rule], verifications: List[Tuple[Packet, str]]):
    for i, (pkt, expected) in enumerate(verifications, 1):
        result = acl_decision(rules, pkt)
        print(f"\n[Verification {i}] expected={expected}, got={result} -> {'PASS' if result==expected else 'FAIL'}")


# ---------------------------
# Hỗ trợ nhập dữ liệu từ bàn phím
# ---------------------------
def input_rangelist(name: str) -> RangeList:
    """
    Nhập rangelist: ví dụ nhập
    3232235776-3232235976,3232236052-3232236082
    hoặc nhập 'any'
    """
    raw = input(f"Nhập {name} (dạng start-end, nhiều khoảng cách nhau dấu phẩy, hoặc 'any'): ").strip()
    if raw.lower() == "any":
        return [(0, 2**32-1)]
    parts = raw.split(",")
    rlist = []
    for p in parts:
        if "-" in p:
            a, b = p.split("-")
            rlist.append((int(a), int(b)))
        else:  # một giá trị đơn
            val = int(p)
            rlist.append((val, val))
    return rlist


def input_value(name: str):
    """Nhập giá trị port hoặc protocol (số hoặc 'any')"""
    raw = input(f"Nhập {name} (số hoặc 'any'): ").strip().lower()
    if raw == "any":
        return "any"
    try:
        return int(raw)
    except:
        return raw


def input_rule(idx: int) -> Rule:
    print(f"\n--- ACL Rule {idx} ---")
    srcIP = input_rangelist("srcIP")
    srcPort = input_value("srcPort")
    dstIP = input_rangelist("dstIP")
    dstPort = input_value("dstPort")
    protocol = input_value("protocol")
    action = input("Nhập action (permit/deny): ").strip().lower()
    return Rule(srcIP, srcPort, dstIP, dstPort, protocol, action, f"L{idx}")


def input_verification(idx: int) -> Tuple[Packet, str]:
    print(f"\n--- Verification Rule {idx} ---")
    srcIP = input_rangelist("srcIP")
    srcPort = input_value("srcPort")
    dstIP = input_rangelist("dstIP")
    dstPort = input_value("dstPort")
    protocol = input_value("protocol")
    expect = input("Nhập expected action (permit/deny): ").strip().lower()
    return (Packet(srcIP, srcPort, dstIP, dstPort, protocol), expect)


# ---------------------------
# Main demo
# ---------------------------
if __name__ == "__main__":
    print("=== Nhập ACL Rules ===")
    n = int(input("Số lượng ACL rules: "))
    rules = []
    for i in range(1, n+1):
        rules.append(input_rule(i))

    print("\n=== Nhập Verification Rules ===")
    m = int(input("Số lượng Verification rules: "))
    verifications = []
    for j in range(1, m+1):
        verifications.append(input_verification(j))

    # Chạy kiểm chứng
    print("\n=== Kết quả kiểm chứng ===")
    verify(rules, verifications)
