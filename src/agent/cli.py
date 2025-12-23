#!/usr/bin/env python
"""
SecureSys Agent - CLI Entry Point

Usage:
    securesys-agent scan [--output json|yaml] [--submit]
    securesys-agent register --api-url <url> --api-key <key>
    securesys-agent --version
    securesys-agent --help
"""

import click
import json
import sys
from datetime import datetime
from pathlib import Path

from .scanner import SystemScanner
from .config import Config, load_config, save_config
from .api_client import SecureSysAPIClient

@click.group()
@click.version_option(version='1.0.0', prog_name='securesys-agent')
def cli():
    """SecureSys Agent - System Security Scanner"""
    pass


@cli.command()
@click.option('--output', '-o', type=click.Choice(['json', 'yaml', 'text']), 
              default='json', help='Output format')
@click.option('--submit', '-s', is_flag=True, help='Submit scan to API')
@click.option('--file', '-f', type=click.Path(), help='Save output to file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(output, submit, file, verbose):
    """Perform a security scan of the local system."""
    
    click.echo(click.style('🔍 SecureSys Agent - Starting Scan', fg='blue', bold=True))
    click.echo(f'   Timestamp: {datetime.now().isoformat()}')
    click.echo()
    
    # Initialize scanner
    scanner = SystemScanner()
    
    # Perform scan
    click.echo('📊 Collecting system information...')
    scan_result = scanner.collect_all()
    
    if verbose:
        click.echo(f'   ✓ Hostname: {scan_result["hostname"]}')
        click.echo(f'   ✓ OS: {scan_result["os"]["name"]} {scan_result["os"]["version"]}')
        click.echo(f'   ✓ Users: {len(scan_result.get("users", {}).get("local_users", []))}')
        click.echo(f'   ✓ Services: {len(scan_result.get("services", []))}')
        click.echo(f'   ✓ Packages: {len(scan_result.get("packages", {}).get("installed", []))}')
    
    # Format output
    if output == 'json':
        output_data = json.dumps(scan_result, indent=2, default=str)
    elif output == 'yaml':
        try:
            import yaml
            output_data = yaml.dump(scan_result, default_flow_style=False)
        except ImportError:
            click.echo(click.style('Warning: PyYAML not installed, using JSON', fg='yellow'))
            output_data = json.dumps(scan_result, indent=2, default=str)
    else:
        output_data = format_text_output(scan_result)
    
    # Save to file if specified
    if file:
        Path(file).write_text(output_data)
        click.echo(f'✓ Output saved to: {file}')
    
    # Submit to API if requested
    if submit:
        click.echo()
        click.echo('📤 Submitting scan to API...')
        
        config = load_config()
        if not config.api_url or not config.api_key:
            click.echo(click.style('Error: API not configured. Run "securesys-agent register" first.', fg='red'))
            sys.exit(1)
        
        client = SecureSysAPIClient(config.api_url, config.api_key)
        
        try:
            # First, ensure system is registered
            system = client.register_or_get_system(
                hostname=scan_result['hostname'],
                os=f"{scan_result['os']['name']} {scan_result['os']['version']}",
                environment='production'
            )
            
            # Submit scan
            result = client.submit_scan(system['id'], scan_result)
            
            click.echo(click.style(f'✓ Scan submitted successfully!', fg='green'))
            click.echo(f'   Scan ID: {result["scan_id"]}')
            click.echo(f'   Status: {result["status"]}')
        except Exception as e:
            click.echo(click.style(f'Error submitting scan: {str(e)}', fg='red'))
            sys.exit(1)
    else:
        # Print output
        click.echo()
        click.echo(output_data)
    
    click.echo()
    click.echo(click.style('✓ Scan completed successfully!', fg='green'))


@cli.command()
@click.option('--api-url', required=True, help='SecureSys API URL')
@click.option('--api-key', required=True, help='API authentication key')
def register(api_url, api_key):
    """Register agent with SecureSys API."""
    
    click.echo(click.style('🔧 Configuring SecureSys Agent', fg='blue', bold=True))
    
    # Validate API connection
    client = SecureSysAPIClient(api_url, api_key)
    
    try:
        if client.health_check():
            click.echo(click.style('✓ API connection successful!', fg='green'))
            
            # Save configuration
            config = Config(api_url=api_url, api_key=api_key)
            save_config(config)
            
            click.echo(click.style('✓ Configuration saved!', fg='green'))
        else:
            click.echo(click.style('Error: Could not connect to API', fg='red'))
            sys.exit(1)
    except Exception as e:
        click.echo(click.style(f'Error: {str(e)}', fg='red'))
        sys.exit(1)


@cli.command()
def status():
    """Show agent configuration status."""
    
    click.echo(click.style('📋 SecureSys Agent Status', fg='blue', bold=True))
    click.echo()
    
    config = load_config()
    
    if config.api_url:
        click.echo(f'   API URL: {config.api_url}')
        click.echo(f'   API Key: {"*" * 8}...{config.api_key[-4:] if config.api_key else "Not set"}')
        
        # Test connection
        client = SecureSysAPIClient(config.api_url, config.api_key)
        try:
            if client.health_check():
                click.echo(click.style('   Connection: ✓ OK', fg='green'))
            else:
                click.echo(click.style('   Connection: ✗ Failed', fg='red'))
        except:
            click.echo(click.style('   Connection: ✗ Error', fg='red'))
    else:
        click.echo('   Status: Not configured')
        click.echo('   Run "securesys-agent register" to configure')


def format_text_output(scan_result):
    """Format scan result as human-readable text."""
    lines = [
        '=' * 60,
        'SECURESYS SYSTEM SCAN REPORT',
        '=' * 60,
        '',
        f'Hostname: {scan_result["hostname"]}',
        f'OS: {scan_result["os"]["name"]} {scan_result["os"]["version"]}',
        f'Scan Time: {scan_result["scan_time"]}',
        '',
        '-' * 40,
        'USERS',
        '-' * 40,
    ]
    
    users = scan_result.get('users', {})
    lines.append(f'Total Users: {len(users.get("local_users", []))}')
    lines.append(f'Admin Users: {len(users.get("admin_users", []))}')
    
    lines.extend([
        '',
        '-' * 40,
        'NETWORK',
        '-' * 40,
    ])
    
    network = scan_result.get('network', {})
    lines.append(f'Open Ports: {len(network.get("open_ports", []))}')
    
    if scan_result.get('firewall', {}).get('enabled'):
        lines.append('Firewall: Enabled')
    else:
        lines.append('Firewall: DISABLED (Warning!)')
    
    lines.extend([
        '',
        '-' * 40,
        'SERVICES',
        '-' * 40,
        f'Running Services: {len(scan_result.get("services", []))}',
        '',
        '=' * 60,
    ])
    
    return '\n'.join(lines)


if __name__ == '__main__':
    cli()
