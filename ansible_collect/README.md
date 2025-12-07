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
5. Move to [analysis](https://github.com/mtask/PyTriage/tree/main/analyze)

The collection is executed with the following options:

```
/root/collect -c /root/config.yaml --collect --capture -if {{ interfaces_string }
```

The variable `interfaces_string` is built dynamically from the ansible facts and includes active ethernet devices. Capture via ansible playbook only supports network capture. Not memory capture. 
You can modify `config.yaml` to skip network capture as well if you want to or specify other capture length than default 60 seconds.

```yaml
modules:
  capture:
    network_timeout: 60
    enable_network: false
    enable_memory: false
```
