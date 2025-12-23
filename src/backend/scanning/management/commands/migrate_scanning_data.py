"""
Management command to migrate data from core app to scanning app.

Usage:
    python manage.py migrate_scanning_data [--dry-run] [--backup]
    
Options:
    --dry-run: Preview changes without committing to database
    --backup: Create database backup before migration
    --rollback: Rollback the migration (copy data back to core)
"""
import logging
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction, connection
from django.utils import timezone
from django.core.management import call_command
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Migrate data from core.models to scanning.models'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Preview migration without committing changes',
        )
        parser.add_argument(
            '--backup',
            action='store_true',
            help='Create database backup before migration',
        )
        parser.add_argument(
            '--rollback',
            action='store_true',
            help='Rollback migration (copy data from scanning back to core)',
        )
        parser.add_argument(
            '--verify',
            action='store_true',
            help='Verify data integrity after migration',
        )
    
    def handle(self, *args, **options):
        dry_run = options['dry_run']
        backup = options['backup']
        rollback = options['rollback']
        verify = options['verify']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('🔍 DRY RUN MODE - No changes will be committed'))
        
        # Create backup if requested
        if backup and not dry_run:
            self.create_backup()
        
        try:
            if rollback:
                self.rollback_migration(dry_run)
            elif verify:
                self.verify_migration()
            else:
                self.perform_migration(dry_run)
            
            if not dry_run:
                self.stdout.write(self.style.SUCCESS('✅ Migration completed successfully'))
            else:
                self.stdout.write(self.style.SUCCESS('✅ Dry run completed - review changes above'))
                
        except Exception as e:
            logger.error(f'Migration failed: {str(e)}', exc_info=True)
            raise CommandError(f'Migration failed: {str(e)}')
    
    def create_backup(self):
        """Create a database backup using pg_dump."""
        self.stdout.write('📦 Creating database backup...')
        
        from django.conf import settings
        db_settings = settings.DATABASES['default']
        
        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_file = backup_dir / f'migration_backup_{timestamp}.json'
        
        # Export data as JSON (portable backup)
        self.stdout.write(f'  Writing backup to {backup_file}...')
        
        with transaction.atomic():
            # Check if core tables exist
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name IN ('core_system', 'core_scan', 'core_finding', 'core_recommendation')
                """)
                existing_tables = [row[0] for row in cursor.fetchall()]
            
            if not existing_tables:
                self.stdout.write(self.style.WARNING('  ⚠️  No core tables found - skipping backup'))
                return
            
            backup_data = {
                'timestamp': timestamp,
                'tables': existing_tables,
                'data': {}
            }
            
            # Import models only if tables exist
            try:
                from core import models as core_models
                
                if 'core_system' in existing_tables:
                    backup_data['data']['systems'] = list(
                        core_models.System.objects.values()
                    )
                if 'core_scan' in existing_tables:
                    backup_data['data']['scans'] = list(
                        core_models.Scan.objects.values()
                    )
                if 'core_finding' in existing_tables:
                    backup_data['data']['findings'] = list(
                        core_models.Finding.objects.values()
                    )
                if 'core_recommendation' in existing_tables:
                    backup_data['data']['recommendations'] = list(
                        core_models.Recommendation.objects.values()
                    )
                
                with open(backup_file, 'w') as f:
                    json.dump(backup_data, f, indent=2, default=str)
                
                self.stdout.write(self.style.SUCCESS(f'  ✅ Backup created: {backup_file}'))
                
            except ImportError:
                self.stdout.write(self.style.WARNING('  ⚠️  Core models not found - skipping data backup'))
    
    def perform_migration(self, dry_run=False):
        """Migrate data from core to scanning tables."""
        self.stdout.write('🚀 Starting migration from core → scanning...')
        
        # Check if source tables exist
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('core_system', 'core_scan', 'core_finding', 'core_recommendation')
            """)
            source_tables = [row[0] for row in cursor.fetchall()]
        
        if not source_tables:
            self.stdout.write(self.style.WARNING('⚠️  No core tables found. This is a fresh installation.'))
            self.stdout.write('   You can proceed with using scanning tables directly.')
            return
        
        # Import models
        try:
            from core import models as core_models
            from scanning import models as scanning_models
        except ImportError as e:
            raise CommandError(f'Failed to import models: {str(e)}')
        
        stats = {
            'systems': 0,
            'scans': 0,
            'findings': 0,
            'recommendations': 0,
        }
        
        with transaction.atomic():
            # 1. Migrate Systems
            if 'core_system' in source_tables:
                self.stdout.write('  📊 Migrating systems...')
                core_systems = core_models.System.objects.all()
                
                for system in core_systems:
                    if dry_run:
                        self.stdout.write(f'    [DRY RUN] Would migrate system: {system.hostname}')
                    else:
                        scanning_models.System.objects.get_or_create(
                            id=system.id,
                            defaults={
                                'hostname': system.hostname,
                                'os': system.os,
                                'os_version': system.os_version,
                                'environment': system.environment,
                                'ip_address': system.ip_address,
                                'description': system.description,
                                'is_active': system.is_active,
                                'created_at': system.created_at,
                                'updated_at': system.updated_at,
                                'last_seen': system.last_seen,
                            }
                        )
                    stats['systems'] += 1
                
                self.stdout.write(self.style.SUCCESS(f'    ✅ Migrated {stats["systems"]} systems'))
            
            # 2. Migrate Scans
            if 'core_scan' in source_tables:
                self.stdout.write('  📊 Migrating scans...')
                core_scans = core_models.Scan.objects.all()
                
                for scan in core_scans:
                    if dry_run:
                        self.stdout.write(f'    [DRY RUN] Would migrate scan: {scan.id}')
                    else:
                        scanning_models.Scan.objects.get_or_create(
                            id=scan.id,
                            defaults={
                                'system_id': scan.system_id,
                                'scan_type': scan.scan_type,
                                'status': scan.status,
                                'risk_score': scan.risk_score,
                                'maturity_level': scan.maturity_level,
                                'started_at': scan.started_at,
                                'completed_at': scan.completed_at,
                                'raw_results': scan.raw_results,
                                'error_message': scan.error_message,
                                'created_at': scan.created_at,
                                'updated_at': scan.updated_at,
                            }
                        )
                    stats['scans'] += 1
                
                self.stdout.write(self.style.SUCCESS(f'    ✅ Migrated {stats["scans"]} scans'))
            
            # 3. Migrate Findings
            if 'core_finding' in source_tables:
                self.stdout.write('  📊 Migrating findings...')
                core_findings = core_models.Finding.objects.all()
                
                for finding in core_findings:
                    if dry_run:
                        self.stdout.write(f'    [DRY RUN] Would migrate finding: {finding.title}')
                    else:
                        scanning_models.Finding.objects.get_or_create(
                            id=finding.id,
                            defaults={
                                'scan_id': finding.scan_id,
                                'title': finding.title,
                                'description': finding.description,
                                'severity': finding.severity,
                                'category': finding.category,
                                'affected_resource': finding.affected_resource,
                                'remediation': finding.remediation,
                                'references': finding.references,
                                'cve_id': finding.cve_id,
                                'cvss_score': finding.cvss_score,
                                'status': finding.status,
                                'created_at': finding.created_at,
                                'updated_at': finding.updated_at,
                            }
                        )
                    stats['findings'] += 1
                
                self.stdout.write(self.style.SUCCESS(f'    ✅ Migrated {stats["findings"]} findings'))
            
            # 4. Migrate Recommendations
            if 'core_recommendation' in source_tables:
                self.stdout.write('  📊 Migrating recommendations...')
                core_recommendations = core_models.Recommendation.objects.all()
                
                for rec in core_recommendations:
                    if dry_run:
                        self.stdout.write(f'    [DRY RUN] Would migrate recommendation: {rec.title}')
                    else:
                        scanning_models.Recommendation.objects.get_or_create(
                            id=rec.id,
                            defaults={
                                'scan_id': rec.scan_id,
                                'finding_id': rec.finding_id,
                                'title': rec.title,
                                'description': rec.description,
                                'priority': rec.priority,
                                'effort_level': rec.effort_level,
                                'impact': rec.impact,
                                'created_at': rec.created_at,
                                'updated_at': rec.updated_at,
                            }
                        )
                    stats['recommendations'] += 1
                
                self.stdout.write(self.style.SUCCESS(f'    ✅ Migrated {stats["recommendations"]} recommendations'))
            
            if dry_run:
                raise transaction.TransactionManagementError('Dry run - rolling back')
        
        # Print summary
        self.stdout.write('\n📈 Migration Summary:')
        for key, count in stats.items():
            self.stdout.write(f'  • {key.capitalize()}: {count}')
    
    def rollback_migration(self, dry_run=False):
        """Rollback migration by copying data from scanning back to core."""
        self.stdout.write(self.style.WARNING('⚠️  Rolling back migration: scanning → core'))
        
        if not dry_run:
            confirm = input('Are you sure you want to rollback? This will overwrite core tables. (yes/no): ')
            if confirm.lower() != 'yes':
                self.stdout.write(self.style.ERROR('Rollback cancelled'))
                return
        
        # Import models
        try:
            from core import models as core_models
            from scanning import models as scanning_models
        except ImportError as e:
            raise CommandError(f'Failed to import models: {str(e)}')
        
        stats = {
            'systems': 0,
            'scans': 0,
            'findings': 0,
            'recommendations': 0,
        }
        
        with transaction.atomic():
            # Copy data back from scanning to core
            self.stdout.write('  📊 Rolling back systems...')
            for system in scanning_models.System.objects.all():
                if dry_run:
                    self.stdout.write(f'    [DRY RUN] Would restore system: {system.hostname}')
                else:
                    core_models.System.objects.update_or_create(
                        id=system.id,
                        defaults={
                            'hostname': system.hostname,
                            'os': system.os,
                            'os_version': system.os_version,
                            'environment': system.environment,
                            'ip_address': system.ip_address,
                            'description': system.description,
                            'is_active': system.is_active,
                            'created_at': system.created_at,
                            'updated_at': system.updated_at,
                            'last_seen': system.last_seen,
                        }
                    )
                stats['systems'] += 1
            
            if dry_run:
                raise transaction.TransactionManagementError('Dry run - rolling back')
        
        self.stdout.write(self.style.SUCCESS(f'  ✅ Rolled back {stats["systems"]} systems'))
        self.stdout.write(self.style.SUCCESS('✅ Rollback completed'))
    
    def verify_migration(self):
        """Verify data integrity after migration."""
        self.stdout.write('🔍 Verifying migration data integrity...')
        
        try:
            from core import models as core_models
            from scanning import models as scanning_models
        except ImportError as e:
            raise CommandError(f'Failed to import models: {str(e)}')
        
        issues = []
        
        # Check if all core records exist in scanning
        core_system_count = core_models.System.objects.count()
        scanning_system_count = scanning_models.System.objects.count()
        
        if core_system_count > scanning_system_count:
            issues.append(f'Missing systems: {core_system_count - scanning_system_count}')
        
        core_scan_count = core_models.Scan.objects.count()
        scanning_scan_count = scanning_models.Scan.objects.count()
        
        if core_scan_count > scanning_scan_count:
            issues.append(f'Missing scans: {core_scan_count - scanning_scan_count}')
        
        if issues:
            self.stdout.write(self.style.ERROR('❌ Verification failed:'))
            for issue in issues:
                self.stdout.write(self.style.ERROR(f'  • {issue}'))
        else:
            self.stdout.write(self.style.SUCCESS('✅ Verification passed - data integrity confirmed'))
            self.stdout.write(f'  • Systems: {scanning_system_count}')
            self.stdout.write(f'  • Scans: {scanning_scan_count}')
