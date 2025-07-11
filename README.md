# Trivy Multi-Image Security Report Generator

A unified HTML report generator for Trivy security scans that combines multiple Docker image scan results into a single interactive dashboard with image selection dropdown.

## Features

- 📊 **Unified Dashboard**: Single HTML report for multiple Docker images
- 🔄 **Interactive Dropdown**: Easy switching between different image scan results
- 🎨 **Clean UI**: Modern, responsive design with severity-based color coding
- 🔍 **Advanced Filtering**: Filter by severity, package, CVE ID, or fix availability
- 📈 **Metrics Overview**: Quick view of vulnerability counts by severity
- 🔗 **Direct CVE Links**: Click-through to NVD for detailed vulnerability information

## Files

- `multi-image-trivy-report-template.html` - HTML template with Bootstrap and DataTables
- `trivy_report_generator.py` - Python script to merge Trivy JSON outputs into the template

## Prerequisites

- **Trivy**: Security scanner (install from https://github.com/aquasecurity/trivy)
- **Python 3.6+**: For running the report generator
- **Docker** (optional): If scanning Docker images

## Quick Start

1. **Scan your Docker images with Trivy:**
```bash
trivy image -f json -o nginx-scan.json nginx:latest
trivy image -f json -o python-scan.json python:3.9-slim
trivy image -f json -o node-scan.json node:16-alpine
```

2. **Generate the unified report:**
```bash
python3 trivy_report_generator.py security-report.html nginx-scan.json python-scan.json node-scan.json
```

3. **Open `security-report.html` in your browser**

## Azure DevOps Pipeline Integration

### Basic Integration

Add this to your `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  # List of images to scan
  imagesToScan: 'myapp:$(Build.BuildId),nginx:latest,postgres:14'

stages:
  - stage: SecurityScan
    jobs:
      - job: TrivyScan
        steps:
          # Install Trivy
          - script: |
              sudo apt-get update
              sudo apt-get install wget apt-transport-https gnupg lsb-release -y
              wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
              echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
              sudo apt-get update
              sudo apt-get install trivy -y
            displayName: 'Install Trivy'

          # Clone this repository to get the templates
          - script: |
              git clone https://github.com/siddharthtanna7/trivy-template.git
              cp trivy-template/*.py .
              cp trivy-template/*.html .
            displayName: 'Get Report Templates'

          # Scan images
          - script: |
              mkdir -p scan-results
              
              # Convert comma-separated list to array
              IFS=',' read -ra IMAGES <<< "$(imagesToScan)"
              
              # Scan each image
              for image in "${IMAGES[@]}"; do
                echo "Scanning: $image"
                filename=$(echo "$image" | sed 's/[^a-zA-Z0-9._-]/-/g')
                trivy image -f json -o "scan-results/${filename}.json" "$image"
              done
              
              # Generate report
              python3 trivy_report_generator.py $(Build.ArtifactStagingDirectory)/security-report.html scan-results/*.json
            displayName: 'Scan Images and Generate Report'

          # Publish report
          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)/security-report.html'
              artifactName: 'security-report'
            displayName: 'Publish Security Report'
```

### Advanced Integration with Parameters

```yaml
parameters:
  - name: imageList
    displayName: 'Docker Images to Scan'
    type: object
    default:
      - 'myapp:latest'
      - 'myapi:latest'
      - 'postgres:14'

  - name: failOnCritical
    displayName: 'Fail build on critical vulnerabilities'
    type: boolean
    default: true

trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: Build
    jobs:
      - job: BuildImages
        steps:
          # Your build steps here
          - script: echo "Building images..."

  - stage: SecurityScan
    dependsOn: Build
    jobs:
      - job: TrivyScan
        steps:
          # Install dependencies
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '3.9'
            displayName: 'Use Python 3.9'

          - script: |
              # Install Trivy
              curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin latest
              
              # Get report templates
              wget https://raw.githubusercontent.com/siddharthtanna7/trivy-template/main/trivy_report_generator.py
              wget https://raw.githubusercontent.com/siddharthtanna7/trivy-template/main/multi-image-trivy-report-template.html
            displayName: 'Setup Tools'

          # Scan each image
          - ${{ each image in parameters.imageList }}:
            - script: |
                echo "Scanning ${{ image }}"
                filename=$(echo "${{ image }}" | sed 's/[^a-zA-Z0-9._-]/-/g')
                trivy image -f json -o "${filename}.json" "${{ image }}"
              displayName: 'Scan ${{ image }}'

          # Generate unified report
          - script: |
              python3 trivy_report_generator.py security-report.html *.json
              
              # Create summary
              echo "## Security Scan Summary" > $(Build.ArtifactStagingDirectory)/summary.md
              echo "" >> $(Build.ArtifactStagingDirectory)/summary.md
              
              # Count vulnerabilities
              total_critical=0
              total_high=0
              
              for json_file in *.json; do
                if [ -f "$json_file" ]; then
                  image_name=$(jq -r '.ArtifactName' "$json_file")
                  critical=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$json_file")
                  high=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$json_file")
                  
                  total_critical=$((total_critical + critical))
                  total_high=$((total_high + high))
                  
                  echo "### $image_name" >> $(Build.ArtifactStagingDirectory)/summary.md
                  echo "- Critical: $critical" >> $(Build.ArtifactStagingDirectory)/summary.md
                  echo "- High: $high" >> $(Build.ArtifactStagingDirectory)/summary.md
                  echo "" >> $(Build.ArtifactStagingDirectory)/summary.md
                fi
              done
              
              # Copy report to artifacts
              cp security-report.html $(Build.ArtifactStagingDirectory)/
              
              # Fail if critical vulnerabilities found
              if [ $total_critical -gt 0 ] && [ "${{ parameters.failOnCritical }}" == "True" ]; then
                echo "##vso[task.logissue type=error]Found $total_critical CRITICAL vulnerabilities!"
                exit 1
              fi
            displayName: 'Generate Report and Check Results'

          # Publish artifacts
          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)'
              artifactName: 'security-reports'
            displayName: 'Publish Reports'

          # Optional: Publish to Wiki or other locations
          - task: PublishHtmlReport@1
            inputs:
              reportDir: '$(Build.ArtifactStagingDirectory)'
              tabName: 'Security Scan'
            displayName: 'Publish to Pipeline'
            continueOnError: true
```

### Integration with Existing Pipeline

If you already have a pipeline, add this job:

```yaml
jobs:
  - job: SecurityScan
    pool:
      vmImage: 'ubuntu-latest'
    steps:
      - checkout: none
      
      - script: |
          # Install required tools
          sudo apt-get update && sudo apt-get install -y python3 python3-pip jq
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          
          # Get templates
          wget https://github.com/siddharthtanna7/trivy-template/raw/main/trivy_report_generator.py
          wget https://github.com/siddharthtanna7/trivy-template/raw/main/multi-image-trivy-report-template.html
        displayName: 'Setup'

      - script: |
          # Define your images
          images=("myapp:latest" "mydb:latest" "cache:latest")
          
          # Scan each
          for img in "${images[@]}"; do
            safe_name=$(echo "$img" | tr ':/' '-')
            trivy image -f json -o "${safe_name}.json" "$img"
          done
          
          # Generate report
          python3 trivy_report_generator.py report.html *.json
        displayName: 'Scan and Report'

      - publish: report.html
        artifact: SecurityReport
```

## Using with Private Registries

For private Docker registries:

```yaml
- task: Docker@2
  inputs:
    command: login
    containerRegistry: 'your-service-connection'

- script: |
    trivy image -f json -o scan.json your-registry.azurecr.io/image:tag
```

## Customization

### Modify Severity Thresholds

Edit the pipeline to fail on different severity levels:

```yaml
- script: |
    high_count=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH" or .Severity=="CRITICAL")] | length' scan.json)
    if [ $high_count -gt 0 ]; then
      echo "##vso[task.complete result=Failed;]Found $high_count HIGH/CRITICAL vulnerabilities"
    fi
```

### Email Notifications

Add email notification with the report:

```yaml
- task: SendEmail@1
  inputs:
    to: 'security-team@company.com'
    subject: 'Security Scan Report - Build $(Build.BuildNumber)'
    body: 'Please find the security scan report attached.'
    attachments: '$(Build.ArtifactStagingDirectory)/security-report.html'
  condition: always()
```

## Troubleshooting

### Common Issues

1. **Trivy installation fails**
   - Use the curl installation method instead of apt
   - Ensure you have sudo permissions

2. **Python script fails**
   - Check Python version (3.6+ required)
   - Ensure all JSON files are valid

3. **No vulnerabilities shown**
   - Verify Trivy scanned successfully
   - Check JSON files are not empty

### Debug Mode

Add debug output to your pipeline:

```yaml
- script: |
    set -x  # Enable debug
    ls -la *.json
    for f in *.json; do
      echo "=== $f ==="
      jq '.ArtifactName' "$f"
    done
  displayName: 'Debug Output'
```

## Contributing

Feel free to submit issues and pull requests at https://github.com/siddharthtanna7/trivy-template

## License

MIT License - See LICENSE file for details