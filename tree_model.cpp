#include "tree_model.h"

TreeModelNode::TreeModelNode() : left(NULL), right(NULL) {}

bool TreeModelNode::is_leaf(TreeModelNode *node) {
    return node->left == NULL && node->right == NULL;
}

std::vector<int> search_tree_model(TreeModelNode *root, std::bitset<RULE_COUNT> packet_bitmap) {
    std::queue<std::pair<TreeModelNode *,int>> bfs_queue;
    bfs_queue.push({root, 0});
    std::vector<int> possible_flows;

    while (!bfs_queue.empty()) {
        std::pair<TreeModelNode *,int> current_node = bfs_queue.front();
        bfs_queue.pop();

        TreeModelNode *current_node_ptr = current_node.first;
        int bit_index = current_node.second;

        if (TreeModelNode::is_leaf(current_node_ptr)) {
            for (int flow : current_node_ptr->flows) possible_flows.push_back(flow);
        }

        if (packet_bitmap[bit_index] == 0) {
            if (current_node_ptr->left != NULL) bfs_queue.push({current_node_ptr->left, bit_index + 1});
        } else {
            if (current_node_ptr->left != NULL) bfs_queue.push({current_node_ptr->left, bit_index + 1});
            if (current_node_ptr->right != NULL) bfs_queue.push({current_node_ptr->right, bit_index + 1});
        }
    }

    return possible_flows;
}

void update_tree_model(TreeModelNode *root, std::bitset<RULE_COUNT> flow_bitmap, int flow_id) {
    TreeModelNode *current_node = root;
    for (int i = 0; i < RULE_COUNT; i++) {
        if (flow_bitmap[i] == 0) {
            if (current_node->left == NULL) {
                current_node->left = new TreeModelNode();
            }
            current_node = current_node->left;
        } else {
            if (current_node->right == NULL) {
                current_node->right = new TreeModelNode();
            }
            current_node = current_node->right;
        }
        if (i == RULE_COUNT - 1) current_node->flows.push_back(flow_id);
    }
}
