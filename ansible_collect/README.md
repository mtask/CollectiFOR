# ansible-collect | Remote collection

Run remote collection with ansible.

```
ansible-playbook [ansible opts] collect.yml
```

Basic flow of the `collect.yml` playbook:

1. Copy `../collect/dist/collec` -> `/root/collect` (collect.py needs to be built to binary. Instructions are [here](https://github.com/mtask/PyTriage/blob/main/collect/README.md).
2. Copy `../collect/config.yaml` -> `/root/config.yaml`
3. Execute collect binary
4. Fetch collection tar.gz -> `{{ playbook_dir }}/fetched_collections`

With fetched collection move to [analysis](https://github.com/mtask/PyTriage/tree/main/analyze)

The collection is executed with the following options:

```
/root/collect -c /root/config.yaml --collect --capture -if {{ interfaces_string }
```

Configuration file is built dynamically from variables defined by default in `group_vars/all.yml`. You can specify different collection sets for different hosts in your inventory by specifying overriding groupvars or hostvars. 
The variable `interfaces_string` is by default built dynamically from the ansible facts and includes active ethernet devices.
You can change this in `group_vars/all.yml`. Capture via ansible playbook only supports network capture. Not memory or disk capture.
Collect binary itself does support remote disk capture over SSH. See here: [https://github.com/mtask/CollectiFOR/tree/main/collect#capture-module--disk](https://github.com/mtask/CollectiFOR/tree/main/collect#capture-module--disk)
