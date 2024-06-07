## High-Performance-Router-Final

### Description
Implement algorithm of field-missing packet recovery.

### Prerequisites
#### Generate test data
1. Get `acl1_1k.txt` and `acl1_1k_trace.txt` from [here](https://github.com/JiaChangGit/network-packet-classification/tree/analyDataset)

2. Run `generate_flow_data.py` to generate test data.
```bash
python generate_flow_data.py
```

### Compile and Run
```bash
g++ main.cpp tree_model.cpp
./a.out
```
