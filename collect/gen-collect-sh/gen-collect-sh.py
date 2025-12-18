import yaml
import json
import argparse
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

def render_template(template_name, output_path, config, template_dir = "templates"):
    env = Environment(
        loader=FileSystemLoader("templates"),
        trim_blocks=True,
        lstrip_blocks=True
    )
    template = env.get_template(template_name)
    rendered = template.render(config=config, collect=config['modules']['collect'], capture=config['modules']['capture'])

    out_file = Path(output_path)
    out_file.write_text(rendered, encoding="utf-8")
    print(f"[+] Generated {out_file}")

if __name__=="__main__":
    parser = argparse.ArgumentParser(
        description="CollectiFOR | generate collect.sh"
    )
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to the YAML configuration file"
    )

    parser.add_argument(
        "output",
        help="Script output name"
    )
    args = parser.parse_args()
    config = load_config(args.config)
    render_template('collect.sh.j2', args.output, config)
