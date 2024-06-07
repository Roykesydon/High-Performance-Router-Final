#include "table_model.h"

TableModel::TableModel() { table = std::vector<std::set<int>>(RULE_COUNT); }

void TableModel::insert(std::bitset<RULE_COUNT> flow_bitmap, int flow_id) {
    for (int i = 0; i < RULE_COUNT; i++) {
        if (flow_bitmap[i] == 1) table[i].insert(flow_id);
    }
}

std::vector<int> TableModel::search(std::bitset<RULE_COUNT> packet_bitmap, int flow_count) {
    std::set<int> impossible_flows;
    std::vector<int> possible_flows;
    for (int i = 0; i < RULE_COUNT; i++) 
        if (packet_bitmap[i] == 0) 
            for (int flow : table[i]) impossible_flows.insert(flow);
    
    for (int i=0; i<flow_count; i++) 
        if (impossible_flows.find(i) == impossible_flows.end()) 
            possible_flows.push_back(i);

    return possible_flows;
}