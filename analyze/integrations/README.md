You can quite easily integrate findings from other tools with python code as long as you can modify results to support schema of the `findings` database table.

```sql
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	case_id INTEGER, 
	case_name VARCHAR, 
	collection_name VARCHAR, 
	timeline_name VARCHAR, 
	type VARCHAR NOT NULL, 
	message VARCHAR NOT NULL, 
	rule VARCHAR, 
	source_file VARCHAR, 
	tags VARCHAR, 
	meta JSON, 
	namespace VARCHAR, 
	artifact VARCHAR, 
	indicator VARCHAR, 
	ack INTEGER, 
	inserted_at DATETIME, 
	PRIMARY KEY (id)
);
```

`sample.py` file shows an sample "integration" where `get_findings` function mimics the 3rd party tool results. Sample script can be launched like this: `python3 -m integrations.sample -c config.yaml`.
