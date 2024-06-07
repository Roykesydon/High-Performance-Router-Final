#include <bitset>
#include <chrono>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <queue>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "constants.h"
#include "table_model.h"
#include "tree_model.h"

using namespace std;

#define ll long long

enum PacketStatus {
    IN_BUFFER,
    COMPLETED,
    CORRECT_RECOVERY,
    WRONG_RECOVERY,
    MATCH_FAILED
};

enum LastCaseType { SINGLE_MATCH, MULTIPLE_MATCHES, NO_MATCH };

class Packet {
   public:
    bitset<RULE_COUNT> missing_fields_bit_match;
    bitset<RULE_COUNT> correct_bit_match;
    bool is_completed = false;
    ll seq_num;
    PacketStatus status;
    LastCaseType last_case_type;

    Packet(bitset<RULE_COUNT> missing_fields_bit_match,
           bitset<RULE_COUNT> correct_bit_match, ll seq_num) {
        this->missing_fields_bit_match = missing_fields_bit_match;
        this->correct_bit_match = correct_bit_match;
        this->seq_num = seq_num;

        if (missing_fields_bit_match == correct_bit_match) {
            this->is_completed = true;
            status = COMPLETED;
        }
    }

    void set_status(PacketStatus status) { this->status = status; }

    void set_last_case_type(LastCaseType last_case_type) {
        this->last_case_type = last_case_type;
    }
};

class BufferPacket {
   public:
    int packet_index;
    int packet_count;
    int flow_count;

    BufferPacket(int packet_index, int packet_count, int flow_count) {
        this->packet_index = packet_index;
        this->packet_count = packet_count;
        this->flow_count = flow_count;
    }
};

unordered_map<bitset<RULE_COUNT>, ll> max_seq_num_map;
unordered_map<bitset<RULE_COUNT>, int> flow_to_id;
unordered_map<int, bitset<RULE_COUNT>> id_to_flow;

list<BufferPacket> buffer;

vector<Packet> packets;

// models
TreeModelNode *root = new TreeModelNode();
TableModel table_model = TableModel();

vector<int> search_possible_flows(bitset<RULE_COUNT> packet_bitmap) {
    vector<int> possible_flow_ids;
    if (packet_bitmap.count() >= TABLE_ONE_THRESHOLD)
        possible_flow_ids =
            table_model.search(packet_bitmap, flow_to_id.size());
    else
        possible_flow_ids = search_tree_model(root, packet_bitmap);

    return possible_flow_ids;
}

void update_packet(int packet_index, int flow_id) {
    packets[packet_index].missing_fields_bit_match = id_to_flow[flow_id];

    if (packets[packet_index].missing_fields_bit_match ==
        packets[packet_index].correct_bit_match) {
        packets[packet_index].set_status(CORRECT_RECOVERY);
    } else
        packets[packet_index].set_status(WRONG_RECOVERY);

    max_seq_num_map[packets[packet_index].missing_fields_bit_match] =
        max(max_seq_num_map[packets[packet_index].missing_fields_bit_match],
            packets[packet_index].seq_num);
}

void add_to_buffer(int packet_index, int packet_count, int flow_count) {
    buffer.push_back(BufferPacket(packet_index, packet_count, flow_count));
    packets[packet_index].set_status(IN_BUFFER);
}

bool in_buffer_match(int packet_index) {
    vector<int> possible_flow_ids;
    Packet packet = packets[packet_index];

    possible_flow_ids =
        search_possible_flows(packets[packet_index].missing_fields_bit_match);

    packets[packet_index].set_last_case_type(
        possible_flow_ids.size() == 1
            ? SINGLE_MATCH
            : (possible_flow_ids.size() > 1 ? MULTIPLE_MATCHES : NO_MATCH));

    if (possible_flow_ids.size() == 1) {  // case 2: single match
        update_packet(packet_index, possible_flow_ids[0]);
        return true;
    } else if (possible_flow_ids.size() > 1) {  // case 3: multiple matches
        vector<int> filtered_possible_flow_ids;
        for (int flow_id : possible_flow_ids) {
            if (abs(max_seq_num_map[id_to_flow[flow_id]] - packet.seq_num) <=
                DELTA)
                filtered_possible_flow_ids.push_back(flow_id);
        }
        if (filtered_possible_flow_ids.size() == 1) {
            update_packet(packet_index, filtered_possible_flow_ids[0]);
            return true;
        }
    }

    return false;
}

void update_buffer(int cur_packet_index, int cur_flow_index,
                   bool update_all = false) {
    vector<int> possible_flow_ids;
    // remove fron buffer
    vector<list<BufferPacket>::iterator> to_remove;

    for (auto it = buffer.begin(); it != buffer.end(); it++) {
        BufferPacket buffer_packet = *it;
        Packet packet = packets[buffer_packet.packet_index];

        if (cur_packet_index - buffer_packet.packet_index >
            MAX_WAITING_PACKETS) {
            in_buffer_match(buffer_packet.packet_index);

            if (packet.status == IN_BUFFER) packet.set_status(MATCH_FAILED);
            to_remove.push_back(it);
            continue;
        } else if (cur_flow_index - buffer_packet.flow_count >
                   MAX_WAITING_FLOWS) {
            in_buffer_match(buffer_packet.packet_index);

            if (packet.status == IN_BUFFER) packet.set_status(MATCH_FAILED);
            to_remove.push_back(it);
        } else {
            if (!update_all) break;
            bool match_success;
            match_success = in_buffer_match(buffer_packet.packet_index);
            if (match_success) to_remove.push_back(it);
        }
    }

    for (auto it : to_remove) buffer.erase(it);
}

int main() {
    const string PACKET_FILE_NAME = "enhanced_acl_1k_trace.txt";

    std::chrono::steady_clock::time_point time_begin, time_end;

    // read packet file
    ifstream packet_file(PACKET_FILE_NAME);
    string line;

    while (getline(packet_file, line)) {
        stringstream ss(line);
        string str;

        ll seq_num;

        ss >> str;
        bitset<RULE_COUNT> missing_fields_bit_match(str);
        ss >> str;
        bitset<RULE_COUNT> correct_bit_match(str);
        ss >> seq_num;

        Packet packet =
            Packet(missing_fields_bit_match, correct_bit_match, seq_num);

        packets.push_back(packet);
    }

    // summary
    cout << "Total packets: " << packets.size() << endl;
    int incomplete_packets = 0;
    for (int i = 0; i < packets.size(); i++)
        if (!packets[i].is_completed) incomplete_packets++;
    cout << "Incomplete packets: " << incomplete_packets << endl;

    // start time
    time_begin = std::chrono::steady_clock::now();

    for (int i = 0; i < packets.size(); i++) {
        Packet packet = packets[i];
        update_buffer(i, flow_to_id.size());

        if (packet.is_completed) {
            max_seq_num_map[packet.missing_fields_bit_match] =
                max(max_seq_num_map[packet.missing_fields_bit_match],
                    packet.seq_num);

            // has new flow
            if (flow_to_id.find(packet.missing_fields_bit_match) ==
                flow_to_id.end()) {
                flow_to_id[packet.missing_fields_bit_match] = flow_to_id.size();
                id_to_flow[flow_to_id[packet.missing_fields_bit_match]] =
                    packet.missing_fields_bit_match;

                update_tree_model(root, packet.missing_fields_bit_match,
                                  flow_to_id[packet.missing_fields_bit_match]);
                table_model.insert(packet.missing_fields_bit_match,
                                   flow_to_id[packet.missing_fields_bit_match]);

                // update buffer
                update_buffer(i, flow_to_id.size(), true);
            }
        } else {  // has missing fields
            vector<int> possible_flow_ids;

            possible_flow_ids =
                search_tree_model(root, packet.missing_fields_bit_match);

            if (possible_flow_ids.size() == 0) {  // case 1: no match
                add_to_buffer(i, i, flow_to_id.size());
            } else if (possible_flow_ids.size() == 1) {  // case 2: single match
                if (packet.seq_num < INITIAL_RANGE) {
                    add_to_buffer(i, i, flow_to_id.size());
                    continue;
                }
                update_packet(i, possible_flow_ids[0]);
            } else {  // case 3: multiple matches
                vector<int> filtered_possible_flow_ids;
                for (int flow_id : possible_flow_ids) {
                    if (abs(max_seq_num_map[id_to_flow[flow_id]] -
                            packet.seq_num) <= DELTA) {
                        filtered_possible_flow_ids.push_back(flow_id);
                    }
                }
                if (filtered_possible_flow_ids.size() == 1 &&
                    packet.seq_num >= INITIAL_RANGE) {
                    update_packet(i, filtered_possible_flow_ids[0]);
                } else {
                    add_to_buffer(i, i, flow_to_id.size());
                }
            }
        }

        if (i % (packets.size() / 10) == 0) {
            time_end = std::chrono::steady_clock::now();
            cout << "Progress: " << (double)i / (double)packets.size() * 100
                 << "%" << endl;
            cout << "Time elapsed: "
                 << int(std::chrono::duration_cast<std::chrono::milliseconds>(
                            time_end - time_begin)
                            .count() /
                        1000.0)
                 << " s" << endl;
        }
    }

    update_buffer(packets.size(), flow_to_id.size(), true);

    // summary packet status
    int correct_recovery = 0;
    int wrong_recovery = 0;
    int in_buffer = 0;
    int match_failed = 0;

    int single_match = 0;
    int multiple_matches = 0;
    int no_match = 0;
    for (int i = 0; i < packets.size(); i++) {
        if (packets[i].status == CORRECT_RECOVERY) correct_recovery++;
        if (packets[i].status == WRONG_RECOVERY) wrong_recovery++;
        if (packets[i].status == IN_BUFFER) {
            in_buffer++;

            if (packets[i].last_case_type == SINGLE_MATCH) single_match++;
            if (packets[i].last_case_type == MULTIPLE_MATCHES)
                multiple_matches++;
            if (packets[i].last_case_type == NO_MATCH) no_match++;
        }
        if (packets[i].status == MATCH_FAILED) match_failed++;
    }
    cout << "-------------------\n";
    cout << "Correct recovery: " << correct_recovery << endl;
    cout << "Wrong recovery: " << wrong_recovery << endl;
    cout << "In buffer: " << in_buffer << endl;
    cout << "Match failed: " << match_failed << endl;
    cout << "In buffer single match: " << single_match << endl;
    cout << "In buffer multiple matches: " << multiple_matches << endl;
    cout << "In buffer no match: " << no_match << endl;
    cout << "-------------------\n";

    // summary
    // calculate accuracy
    int correct_packets = 0;
    for (int i = 0; i < packets.size(); i++)
        if (packets[i].missing_fields_bit_match == packets[i].correct_bit_match)
            correct_packets++;
    cout << "Wrong packets after recovery: " << packets.size() - correct_packets
         << endl;
    cout << "Accuracy: "
         << (double)correct_packets / (double)packets.size() * 100 << "%"
         << endl;

    return 0;
}