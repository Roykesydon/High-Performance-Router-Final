#include <vector>
#include <bitset>
#include <queue>
#include "constants.h"

class TreeModelNode {
public:
    std::vector<int> flows;
    TreeModelNode *left;
    TreeModelNode *right;
    TreeModelNode();

    static bool is_leaf(TreeModelNode *node);
};

std::vector<int> search_tree_model(TreeModelNode *root, std::bitset<RULE_COUNT> packet_bitmap);
void update_tree_model(TreeModelNode *root, std::bitset<RULE_COUNT> flow_bitmap, int flow_id);
