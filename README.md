# 🏭 Snyk plugin for Copacetic

This is a plugin for [Copacetic](https://github.com/project-copacetic/copacetic) to support patching of Snyk CVE reports.

Learn more about Copacetic's scanner plugins [here](https://project-copacetic.github.io/copacetic/website/next/scanner-plugins).

### Build from source

Clone the repository:
```bash
git clone https://github.com/rsashank/copa-snyk.git
cd copa-snyk
```

Build the plugin binary using Make:
```bash
make build
```

Add to path:
```bash
sudo mv copa-snyk /usr/local/bin/
```

### Usage

```bash
# Run Snyk on your project to produce a JSON report:
snyk container test $IMAGE --json > snyk-report.json

# Run copa-snyk to convert the report
# Use the plugin  to parse the Snyk report and output Copa-compatible vulnerability data:
copa-snyk snyk-report.json > copa-snyk-report.json

# Run copa with scanner plugin and report file
copa patch -i $IMAGE -r copa-snyk-report.json --scanner snyk
```
