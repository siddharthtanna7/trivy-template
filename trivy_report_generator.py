#!/usr/bin/env python3
"""
Trivy Report Generator
Converts multiple Trivy JSON scan results into a single HTML report
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path


def parse_trivy_json(json_file):
    """Parse a Trivy JSON report and extract relevant data"""
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    # Extract image info
    image_name = data.get('ArtifactName', 'unknown')
    target_info = f"{image_name}"
    
    # Add OS info if available
    if 'Metadata' in data and 'OS' in data['Metadata']:
        os_info = data['Metadata']['OS']
        family = os_info.get('Family', '')
        name = os_info.get('Name', '')
        if family and name:
            target_info += f" ({family} {name})"
    
    # Extract scan date
    scan_date = data.get('CreatedAt', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    if 'T' in scan_date:  # Convert ISO format to readable format
        try:
            # Handle nanoseconds in timestamp
            if '.' in scan_date:
                date_part, tz_part = scan_date.split('+') if '+' in scan_date else (scan_date.split('-')[-2], scan_date.split('-')[-1])
                if '+' in scan_date:
                    date_main, nano = date_part.rsplit('.', 1)
                    # Truncate nanoseconds to microseconds (6 digits)
                    micro = nano[:6]
                    scan_date = f"{date_main}.{micro}+{tz_part}"
                scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
            else:
                scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
        except:
            # If parsing fails, use the original string
            pass
    
    # Initialize metrics
    metrics = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'UNKNOWN': 0,
        'TOTAL': 0
    }
    
    # Collect vulnerabilities
    vulnerabilities = []
    
    # Process results
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severity = vuln.get('Severity', 'UNKNOWN').upper()
            
            # Update metrics
            if severity in metrics:
                metrics[severity] += 1
            else:
                metrics['UNKNOWN'] += 1
            metrics['TOTAL'] += 1
            
            # Extract vulnerability details
            vuln_data = {
                'package': vuln.get('PkgName', 'unknown'),
                'version': vuln.get('InstalledVersion', 'unknown'),
                'cve': vuln.get('VulnerabilityID', 'unknown'),
                'severity': severity,
                'description': vuln.get('Title', vuln.get('Description', 'No description available')),
                'fixedVersion': vuln.get('FixedVersion', ''),
                'hasFix': 'yes' if vuln.get('FixedVersion') else 'no'
            }
            
            vulnerabilities.append(vuln_data)
    
    return {
        'target': target_info,
        'scanDate': scan_date,
        'metrics': metrics,
        'vulnerabilities': vulnerabilities
    }


def generate_html_report(scan_results, template_file, output_file):
    """Generate HTML report from scan results using the template"""
    
    # Read the template
    with open(template_file, 'r') as f:
        html_content = f.read()
    
    # Convert scan results to JavaScript object
    js_data = json.dumps(scan_results, indent=4)
    
    # Find and replace the scanData object
    start_marker = 'const scanData = {'
    
    # Find start position
    start_idx = html_content.find(start_marker)
    if start_idx == -1:
        print("Error: Could not find scanData marker in template")
        return False
    
    # Find the end of the scanData object by counting brackets
    bracket_count = 0
    in_string = False
    escape_next = False
    
    for i in range(start_idx + len(start_marker) - 1, len(html_content)):
        char = html_content[i]
        
        if escape_next:
            escape_next = False
            continue
            
        if char == '\\':
            escape_next = True
            continue
            
        if char == '"' and not in_string:
            in_string = True
        elif char == '"' and in_string:
            in_string = False
        elif not in_string:
            if char == '{':
                bracket_count += 1
            elif char == '}':
                bracket_count -= 1
                if bracket_count == 0:
                    # Found the end of scanData object
                    end_idx = i + 1
                    
                    # Replace the scanData with our data
                    new_html = (
                        html_content[:start_idx] +
                        f'const scanData = {js_data}' +
                        html_content[end_idx:]
                    )
                    
                    # Write the output file
                    with open(output_file, 'w') as f:
                        f.write(new_html)
                    
                    return True
    
    print("Error: Could not find end of scanData object")
    return False


def main():
    if len(sys.argv) < 3:
        print("Usage: python trivy_report_generator.py <output.html> <trivy-json-file1> [trivy-json-file2] ...")
        print("Example: python trivy_report_generator.py report.html node-scan.json python-scan.json")
        sys.exit(1)
    
    output_file = sys.argv[1]
    json_files = sys.argv[2:]
    
    # Check if template exists
    template_file = 'multi-image-trivy-report-template.html'
    if not os.path.exists(template_file):
        print(f"Error: Template file '{template_file}' not found")
        sys.exit(1)
    
    # Process all JSON files
    scan_results = {}
    
    for json_file in json_files:
        if not os.path.exists(json_file):
            print(f"Warning: File '{json_file}' not found, skipping...")
            continue
        
        try:
            print(f"Processing {json_file}...")
            result = parse_trivy_json(json_file)
            
            # Use the artifact name as the key
            with open(json_file, 'r') as f:
                data = json.load(f)
                image_name = data.get('ArtifactName', Path(json_file).stem)
            
            scan_results[image_name] = result
            print(f"  - Found {result['metrics']['TOTAL']} vulnerabilities")
            
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            continue
    
    if not scan_results:
        print("Error: No valid scan results found")
        sys.exit(1)
    
    # Generate the HTML report
    print(f"\nGenerating HTML report: {output_file}")
    if generate_html_report(scan_results, template_file, output_file):
        print(f"Report generated successfully: {output_file}")
        print(f"Total images scanned: {len(scan_results)}")
    else:
        print("Error generating report")
        sys.exit(1)


if __name__ == '__main__':
    main()