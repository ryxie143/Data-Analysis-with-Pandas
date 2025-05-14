from jinja2 import Template

def generate_report(results):
    with open('template.html', 'r', encoding='utf-8') as f:
        template = Template(f.read())
    rendered = template.render(results=results)
    with open('report.html', 'w', encoding='utf-8') as f:
        f.write(rendered)
    print("[+] Report generated as report.html")
