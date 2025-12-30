"""
Django management command to generate synthetic data for SecureSys Auditor.

Usage:
    python manage.py generate_synth_data
    python manage.py generate_synth_data --systems 20 --scans 5
    python manage.py generate_synth_data --clear  # Clear existing data first
"""

import random
from datetime import timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import transaction

from scanning.models import System, Scan, Finding, Recommendation


User = get_user_model()


class Command(BaseCommand):
    help = 'Generate synthetic data for testing SecureSys Auditor'

    def add_arguments(self, parser):
        parser.add_argument(
            '--systems',
            type=int,
            default=15,
            help='Number of systems to create (default: 15)',
        )
        parser.add_argument(
            '--scans',
            type=int,
            default=3,
            help='Maximum scans per system (default: 3)',
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing synthetic data before generating new data',
        )

    def handle(self, *args, **options):
        num_systems = options['systems']
        max_scans = options['scans']
        clear_data = options['clear']

        self.stdout.write(self.style.SUCCESS('\n' + '=' * 60))
        self.stdout.write(self.style.SUCCESS('🔐 SecureSys Auditor - Synthetic Data Generator'))
        self.stdout.write(self.style.SUCCESS('=' * 60))

        if clear_data:
            self.clear_existing_data()

        try:
            with transaction.atomic():
                users = self.create_users()
                systems = self.create_systems(num_systems)
                scans, findings, recommendations = self.create_scans_and_findings(
                    systems, max_scans
                )
                self.print_summary(users, systems, scans, findings, recommendations)
        except Exception as e:
            raise CommandError(f'Error generating data: {e}')

    def clear_existing_data(self):
        """Clear existing synthetic data."""
        self.stdout.write('\n🗑️  Clearing existing data...')
        
        # Only delete test users (not superusers unless they're test accounts)
        test_emails = [
            'auditor@securesys.local',
            'analyst@securesys.local', 
            'viewer@securesys.local',
            'operations@securesys.local',
        ]
        deleted_users = User.objects.filter(email__in=test_emails).delete()
        self.stdout.write(f'   Deleted {deleted_users[0]} test users')
        
        # Delete all findings first (cascades recommendations)
        deleted_recommendations = Recommendation.objects.all().delete()
        deleted_findings = Finding.objects.all().delete()
        deleted_scans = Scan.objects.all().delete()
        deleted_systems = System.objects.all().delete()
        
        self.stdout.write(f'   Deleted {deleted_systems[0]} systems')
        self.stdout.write(f'   Deleted {deleted_scans[0]} scans')
        self.stdout.write(f'   Deleted {deleted_findings[0]} findings')
        self.stdout.write(f'   Deleted {deleted_recommendations[0]} recommendations')

    def create_users(self):
        """Create test users with different roles."""
        users = []
        
        self.stdout.write('\n👥 Creating test users...')
        
        # Admin user
        admin, created = User.objects.get_or_create(
            email='test@test.com',
            defaults={
                'first_name': 'Test',
                'last_name': 'Admin',
                'role': 'admin',
                'is_active': True,
                'is_staff': True,
                'is_superuser': True,
            }
        )
        if created:
            admin.set_password('test123')
            admin.save()
            self.stdout.write(f'   ✓ Created admin: {admin.email}')
        else:
            self.stdout.write(f'   • Admin exists: {admin.email}')
        users.append(admin)
        
        # Other users
        test_users = [
            ('auditor@securesys.local', 'Sarah', 'Chen', 'auditor'),
            ('analyst@securesys.local', 'James', 'Wilson', 'auditor'),
            ('viewer@securesys.local', 'Maria', 'Garcia', 'viewer'),
            ('operations@securesys.local', 'Alex', 'Johnson', 'viewer'),
        ]
        
        for email, first_name, last_name, role in test_users:
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'first_name': first_name,
                    'last_name': last_name,
                    'role': role,
                    'is_active': True,
                }
            )
            if created:
                user.set_password('SecureSys2024!')
                user.save()
                self.stdout.write(f'   ✓ Created {role}: {email}')
            users.append(user)
        
        return users

    def create_systems(self, num_systems):
        """Create diverse system records."""
        systems = []
        
        self.stdout.write(f'\n📦 Creating {num_systems} systems...')
        
        hostnames = [
            'web-server-prod-{}', 'api-gateway-{}', 'database-master-{}',
            'cache-server-{}', 'load-balancer-{}', 'monitoring-server-{}',
            'ci-cd-runner-{}', 'auth-server-{}', 'worker-node-{}',
            'file-storage-{}', 'backup-server-{}', 'logging-server-{}',
            'analytics-server-{}', 'scheduler-{}', 'proxy-server-{}',
        ]
        
        os_options = [
            ('Ubuntu Server', ['20.04 LTS', '22.04 LTS', '24.04 LTS']),
            ('CentOS Stream', ['8', '9']),
            ('Rocky Linux', ['8.9', '9.3']),
            ('Debian', ['11 Bullseye', '12 Bookworm']),
            ('Windows Server', ['2019', '2022']),
            ('Amazon Linux', ['2', '2023']),
        ]
        
        environments = ['development', 'staging', 'production', 'testing']
        env_weights = [15, 20, 45, 20]
        
        for i in range(num_systems):
            hostname = random.choice(hostnames).format(str(i + 1).zfill(2))
            os_name, os_versions = random.choice(os_options)
            os_version = random.choice(os_versions)
            environment = random.choices(environments, weights=env_weights, k=1)[0]
            
            ip_prefix = {
                'production': '10.0.1.',
                'staging': '10.0.2.',
                'development': '192.168.1.',
                'testing': '192.168.10.',
            }.get(environment, '10.0.1.')
            
            system, created = System.objects.get_or_create(
                hostname=hostname,
                defaults={
                    'os': os_name,
                    'os_version': os_version,
                    'environment': environment,
                    'ip_address': f'{ip_prefix}{random.randint(1, 254)}',
                    'description': f'Auto-generated {environment} {os_name} system',
                    'is_active': True,
                    'last_seen': timezone.now() - timedelta(days=random.uniform(0, 7)),
                }
            )
            
            if created:
                self.stdout.write(f'   ✓ {hostname} ({environment})')
            systems.append(system)
        
        return systems

    def create_scans_and_findings(self, systems, max_scans):
        """Create scans with findings and recommendations."""
        all_scans = []
        all_findings = []
        all_recommendations = []
        
        finding_templates = self.get_finding_templates()
        recommendation_templates = self.get_recommendation_templates()
        
        self.stdout.write(f'\n🔍 Creating scans for {len(systems)} systems...')
        
        for system in systems:
            num_scans = random.randint(1, max_scans)
            
            for _ in range(num_scans):
                scan_type = random.choice(['full', 'quick', 'compliance', 'vulnerability'])
                scan_date = timezone.now() - timedelta(days=random.uniform(0, 30))
                status = random.choices(
                    ['completed', 'processing', 'failed'],
                    weights=[85, 10, 5], k=1
                )[0]
                
                scan = Scan.objects.create(
                    system=system,
                    scan_type=scan_type,
                    status=status,
                    scan_payload=self.generate_payload(system) if status == 'completed' else {},
                    started_at=scan_date,
                )
                
                if status == 'completed':
                    scan_findings = []
                    num_findings = {
                        'production': random.randint(3, 12),
                        'staging': random.randint(2, 8),
                        'development': random.randint(1, 6),
                        'testing': random.randint(0, 4),
                    }.get(system.environment, 3)
                    
                    for severity in ['critical', 'high', 'medium', 'low']:
                        weights = {'critical': 0.05, 'high': 0.15, 'medium': 0.35, 'low': 0.45}
                        count = max(0, int(num_findings * weights[severity]))
                        
                        for _ in range(count):
                            template = random.choice(finding_templates[severity])
                            days_old = (timezone.now() - scan_date).days
                            is_resolved = random.random() < (days_old / 60)
                            
                            finding = Finding.objects.create(
                                scan=scan,
                                category=template['category'],
                                severity=severity,
                                title=template['title'],
                                description=template['description'],
                                cwe_id=template.get('cwe_id', ''),
                                cvss_score=template.get('cvss_score'),
                                evidence={'detection_method': 'automated_scan'},
                                is_resolved=is_resolved,
                                resolved_at=timezone.now() if is_resolved else None,
                            )
                            scan_findings.append(finding)
                            all_findings.append(finding)
                            
                            rec_template = recommendation_templates.get(
                                template['category'],
                                recommendation_templates['other']
                            )
                            recommendation = Recommendation.objects.create(
                                finding=finding,
                                priority=severity,
                                effort=random.choice(['low', 'medium', 'high']),
                                title=rec_template['title'],
                                description=rec_template['description'],
                                steps=rec_template['steps'],
                            )
                            all_recommendations.append(recommendation)
                    
                    # Calculate scores
                    risk_score = self.calculate_risk_score(scan_findings)
                    maturity_level = self.determine_maturity(risk_score)
                    
                    scan.risk_score = risk_score
                    scan.maturity_level = maturity_level
                    scan.completed_at = scan_date + timedelta(minutes=random.randint(2, 30))
                    scan.save()
                    
                    # Update system
                    system.latest_risk_score = risk_score
                    system.latest_maturity_level = maturity_level
                    system.last_seen = scan_date
                    system.save()
                    
                elif status == 'failed':
                    scan.error_message = 'Connection timeout - unable to reach agent'
                    scan.save()
                
                all_scans.append(scan)
        
        return all_scans, all_findings, all_recommendations

    def generate_payload(self, system):
        """Generate realistic scan payload."""
        return {
            'agent_version': f'1.{random.randint(0, 5)}.{random.randint(0, 20)}',
            'system_info': {
                'hostname': system.hostname,
                'os': system.os,
            },
            'collectors': {
                'packages': {'status': 'completed', 'items_checked': random.randint(200, 1500)},
                'services': {'status': 'completed', 'items_checked': random.randint(50, 200)},
            },
        }

    def calculate_risk_score(self, findings):
        """Calculate risk score from findings."""
        if not findings:
            return random.randint(0, 15)
        weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        total = sum(weights.get(f.severity, 0) for f in findings)
        return min(100, max(0, total + random.randint(-5, 10)))

    def determine_maturity(self, risk_score):
        """Determine maturity level from risk score."""
        if risk_score >= 75:
            return 'reactive'
        elif risk_score >= 50:
            return 'basic'
        elif risk_score >= 25:
            return 'managed'
        return 'optimized'

    def get_finding_templates(self):
        """Return finding templates by severity."""
        return {
            'critical': [
                {'title': 'Remote Code Execution Vulnerability', 'description': 'Critical RCE vulnerability found.', 'category': 'patch_management', 'cwe_id': 'CWE-94', 'cvss_score': 9.8},
                {'title': 'SQL Injection in Authentication', 'description': 'SQL injection in login endpoint.', 'category': 'authentication', 'cwe_id': 'CWE-89', 'cvss_score': 9.1},
                {'title': 'Hardcoded Credentials', 'description': 'Credentials exposed in config.', 'category': 'configuration', 'cwe_id': 'CWE-798', 'cvss_score': 9.0},
            ],
            'high': [
                {'title': 'Outdated OpenSSL Library', 'description': 'OpenSSL with known vulnerabilities.', 'category': 'patch_management', 'cwe_id': 'CWE-327', 'cvss_score': 8.1},
                {'title': 'SSH Root Login Enabled', 'description': 'Direct root login allowed via SSH.', 'category': 'configuration', 'cwe_id': 'CWE-250', 'cvss_score': 7.5},
                {'title': 'Missing Security Headers', 'description': 'Critical HTTP headers missing.', 'category': 'configuration', 'cwe_id': 'CWE-693', 'cvss_score': 7.2},
                {'title': 'Weak Password Policy', 'description': 'Insufficient password requirements.', 'category': 'authentication', 'cwe_id': 'CWE-521', 'cvss_score': 7.8},
            ],
            'medium': [
                {'title': 'TLS 1.0/1.1 Supported', 'description': 'Deprecated TLS versions enabled.', 'category': 'encryption', 'cwe_id': 'CWE-326', 'cvss_score': 5.3},
                {'title': 'Insufficient Logging', 'description': 'Security events not logged.', 'category': 'logging', 'cwe_id': 'CWE-778', 'cvss_score': 5.1},
                {'title': 'Missing Rate Limiting', 'description': 'No brute-force protection.', 'category': 'authentication', 'cwe_id': 'CWE-307', 'cvss_score': 6.5},
                {'title': 'Long Session Timeout', 'description': 'Sessions valid for too long.', 'category': 'authentication', 'cwe_id': 'CWE-613', 'cvss_score': 5.4},
            ],
            'low': [
                {'title': 'Information Disclosure', 'description': 'Verbose error messages.', 'category': 'configuration', 'cwe_id': 'CWE-209', 'cvss_score': 3.1},
                {'title': 'Banner Grabbing', 'description': 'Server version disclosed.', 'category': 'configuration', 'cwe_id': 'CWE-200', 'cvss_score': 3.5},
                {'title': 'Missing CAA Records', 'description': 'No DNS CAA records.', 'category': 'network', 'cwe_id': 'CWE-295', 'cvss_score': 3.7},
                {'title': 'Cookie Missing Secure Flag', 'description': 'Cookies without Secure flag.', 'category': 'configuration', 'cwe_id': 'CWE-614', 'cvss_score': 3.1},
            ],
        }

    def get_recommendation_templates(self):
        """Return recommendation templates by category."""
        return {
            'patch_management': {
                'title': 'Apply Security Patches',
                'description': 'Update affected software to patched versions.',
                'steps': ['Backup system', 'Test in staging', 'Apply patches', 'Verify functionality'],
            },
            'configuration': {
                'title': 'Harden Configuration',
                'description': 'Apply security hardening measures.',
                'steps': ['Review baseline', 'Apply CIS benchmarks', 'Test changes', 'Document'],
            },
            'authentication': {
                'title': 'Strengthen Authentication',
                'description': 'Implement stronger authentication controls.',
                'steps': ['Enable MFA', 'Enforce password policy', 'Enable logging', 'Test'],
            },
            'encryption': {
                'title': 'Upgrade Encryption',
                'description': 'Use modern encryption protocols.',
                'steps': ['Disable weak ciphers', 'Enable TLS 1.3', 'Update certificates', 'Verify'],
            },
            'logging': {
                'title': 'Enable Comprehensive Logging',
                'description': 'Configure security event logging.',
                'steps': ['Define requirements', 'Configure audit', 'Set retention', 'Test alerts'],
            },
            'network': {
                'title': 'Secure Network Configuration',
                'description': 'Implement network security controls.',
                'steps': ['Document topology', 'Configure firewall', 'Segment network', 'Monitor'],
            },
            'access_control': {
                'title': 'Implement Least Privilege',
                'description': 'Restrict access based on need.',
                'steps': ['Audit permissions', 'Define RBAC', 'Remove excess access', 'Review regularly'],
            },
            'other': {
                'title': 'Address Security Finding',
                'description': 'Remediate the identified issue.',
                'steps': ['Review finding', 'Research fix', 'Implement', 'Verify'],
            },
        }

    def print_summary(self, users, systems, scans, findings, recommendations):
        """Print summary of generated data."""
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('📊 SYNTHETIC DATA GENERATION COMPLETE'))
        self.stdout.write('=' * 60)
        
        self.stdout.write(f'\n👥 Users: {len(users)}')
        self.stdout.write(f'🖥️  Systems: {len(systems)}')
        self.stdout.write(f'🔍 Scans: {len(scans)}')
        self.stdout.write(f'⚠️  Findings: {len(findings)}')
        self.stdout.write(f'💡 Recommendations: {len(recommendations)}')
        
        # Severity breakdown
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        self.stdout.write('\n📈 Findings by Severity:')
        for sev in ['critical', 'high', 'medium', 'low']:
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[sev]
            self.stdout.write(f'   {icon} {sev.capitalize()}: {severity_counts.get(sev, 0)}')
        
        resolved = sum(1 for f in findings if f.is_resolved)
        if findings:
            self.stdout.write(f'   ✓ Resolved: {resolved} ({resolved/len(findings)*100:.1f}%)')
        
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('🚀 Login credentials:'))
        self.stdout.write('=' * 60)
        self.stdout.write('   Email:    test@test.com')
        self.stdout.write('   Password: test123')
        self.stdout.write('\n   Dashboard: http://127.0.0.1:5173/dashboard')
        self.stdout.write('=' * 60 + '\n')
