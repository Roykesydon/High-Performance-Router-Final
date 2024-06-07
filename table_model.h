#include <bitset>
#include <queue>
#include <set>
#include <vector>

#include "constants.h"

class TableModel {
   public:
    // vector<set> outer has size RULE_COUNT

    std::vector<std::set<int>> table;
    TableModel();

    void insert(std::bitset<RULE_COUNT> flow_bitmap, int flow_id);
    std::vector<int> search(std::bitset<RULE_COUNT> packet_bitmap, int flow_count);
};
