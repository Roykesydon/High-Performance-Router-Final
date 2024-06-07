import ipaddress
import random

RULE_LIMIT = 1000


def read_acl_rules(filename):
    rules = []
    with open(filename, "r") as file:
        for line in file:
            line = line[1:]
            line = line.replace(" : ", ":")
            parts = line.split()
            if parts:
                print
                rule = {
                    "src_ip": ipaddress.ip_network(parts[0]),
                    "dst_ip": ipaddress.ip_network(parts[1]),
                    "src_port_range": tuple(map(int, parts[2].split(":"))),
                    "dst_port_range": tuple(map(int, parts[3].split(":"))),
                    "protocol": int(parts[4].split("/")[0], 16),
                    "tcp_flags": int(parts[5].split("/")[0], 16),
                }
                rules.append(rule)
    return rules

def match_rules_to_bit_match(rules, matched_rules):
    bit_match = "0" * len(rules)
    for rule_index in matched_rules:
        bit_match = bit_match[:rule_index] + "1" + bit_match[rule_index + 1 :]
    
    return bit_match

def match_packet_to_rules(
    packet,
    rules,
    choose_columns=[
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "tcp_flags",
    ],
) -> list:
    col_matched_rules = {}
    final_matched_rules = []
    for column in choose_columns:
        matched_rules = []
        for index, rule in enumerate(rules):
            if (
                column in ["src_ip", "dst_ip"]
                and rule[column].network_address
                <= ipaddress.ip_address(packet[column])
                <= rule[column].broadcast_address
            ):
                matched_rules.append(index)
            elif (
                column in ["src_port", "dst_port"]
                and rule[column + "_range"][0]
                <= packet[column]
                <= rule[column + "_range"][1]
            ):
                matched_rules.append(index)
            elif column == "protocol" and rule[column] == packet[column]:
                matched_rules.append(index)
            elif column == "tcp_flags" and rule[column] == (
                packet[column] & rule[column]
            ):
                matched_rules.append(index)

        col_matched_rules[column] = matched_rules

    # use "and" operation to get the final matched rules
    for index in col_matched_rules:
        if not final_matched_rules:
            final_matched_rules = col_matched_rules[index]
        else:
            final_matched_rules = list(
                set(final_matched_rules).intersection(set(col_matched_rules[index]))
            )

    return final_matched_rules


def process_trace(trace_filename, acl_filename, output_filename):
    rules = read_acl_rules(acl_filename)
    FIELD_MISSING_PROB = 0.1


    bit_match_count = {}
    bit_match_to_packet = {}

    packets = []
    matched_rules = []
    fail_match_count = 0

    with open(trace_filename, "r") as file, open(output_filename, "w") as output:
        for line in file:
            parts = line.split()
            if parts:
                packet = {
                    "src_ip": int(parts[0]),
                    "dst_ip": int(parts[1]),
                    "src_port": int(parts[2]),
                    "dst_port": int(parts[3]),
                    "protocol": int(parts[4]),
                    "tcp_flags": int(parts[5]),
                    # "rule_index": int(parts[6]),
                }
                packets.append(packet)

        """
        Choose the rules that are matched most frequently
        """

        for index, packet in enumerate(packets):
            matched_rules = match_packet_to_rules(packet, rules)
            # print(f"Matched {len(matched_rules)} rules")

            if len(matched_rules) == 0:
                fail_match_count += 1
                continue

            bit_match = match_rules_to_bit_match(rules, matched_rules)

            bit_match_count[bit_match] = bit_match_count.get(bit_match, 0) + 1
            if bit_match not in bit_match_to_packet:
                bit_match_to_packet[bit_match] = packet

            if index % (len(packets) // 10) == 0:
                print(f"Processed {index} packets")

        print(f"len(bit_match_count): {len(bit_match_count)}")
        print(f"Failed to match {fail_match_count} packets")

        flows_count = {}
        flows_start = {}
        
        not_same_bitmatch_count = 0
        total_count = 0
        loop_count = 0

        while True:
            if len(bit_match_to_packet) == 0:
                break

            flow_bitmatch, packet = random.choice(list(bit_match_to_packet.items()))

            if loop_count % 2 == 0 and loop_count != 0:
                flow_bitmatch = random.choice(list(flows_count.keys()))

            if flow_bitmatch not in flows_count:
                flows_start[flow_bitmatch] = random.randint(0, 1000)
                flows_count[flow_bitmatch] = flows_start[flow_bitmatch]
            if flows_count[flow_bitmatch] == flows_start[flow_bitmatch] + 100:
                del bit_match_to_packet[flow_bitmatch]
                continue

            iteration = random.randint(10, 30)
            for i in range(iteration):
                k_v_list = list(packet.items())
                sort_columns = [
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "protocol",
                    "tcp_flags",
                ]
                missing_columns = sort_columns
                # use FIELD_MISSING_PROB to decide which field to
                missing_columns = [
                    column
                    for column in missing_columns
                    if random.random() > FIELD_MISSING_PROB
                ]
                
                matched_rules = match_packet_to_rules(packet, rules, missing_columns)
                bit_match = match_rules_to_bit_match(rules, matched_rules)
                
                output.write(f"{bit_match} {flow_bitmatch} {flows_count[flow_bitmatch]}\n")
                
                if bit_match != flow_bitmatch:
                    not_same_bitmatch_count += 1
                total_count += 1
                
                flows_count[flow_bitmatch] += 1
                if flows_count[flow_bitmatch] == flows_start[flow_bitmatch] + 100:
                    del bit_match_to_packet[flow_bitmatch]
                    break

        assert len(bit_match_to_packet) == 0
        for flow_bit_match in flows_count:
            assert flows_count[flow_bit_match] == flows_start[flow_bit_match] + 100

        print(f"not_same_bitmatch_count: {not_same_bitmatch_count}")
        print(f"total_count: {total_count}")


# Replace 'acl_1k.txt', 'acl_1k_trace.txt', and 'output_filename.txt' with the actual file paths
process_trace("acl1_1k_trace.txt", "acl1_1k.txt", "enhanced_acl_1k_trace.txt")
